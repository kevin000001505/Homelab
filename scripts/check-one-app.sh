#!/usr/bin/env bash
#
# check-one-app.sh <config> <app-name>
#
# Checks a SINGLE app (by its "name" field in apps.yaml) against its
# upstream registry. If the latest tag matching tag_pattern is newer
# than what's currently pinned in the manifest, patches the manifest
# in place.
#
# This script only proposes changes to a file on disk — it never touches
# the cluster. Deployment happens via ArgoCD after the resulting PR is
# reviewed and merged.
#
# Outputs (appended to $GITHUB_OUTPUT when set):
#   changed=true|false
#   name=<app name>
#   current=<currently pinned version>
#   latest=<newest matching version>
#
# Requires: yq (mikefarah/yq v4+), skopeo

set -euo pipefail

CONFIG="${1:?usage: check-one-app.sh <config> <app-name>}"
APP_NAME="${2:?usage: check-one-app.sh <config> <app-name>}"

emit() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "$1" >> "$GITHUB_OUTPUT"
  fi
}

# Resolve the app's index by matching its "name" field, so every
# downstream .[$IDX].xxx lookup below stays unchanged. If no app in
# apps.yaml has this name, IDX comes back empty and we fail clearly
# instead of silently querying index "null".
IDX=$(yq -r "(.[] | select(.name == \"${APP_NAME}\") | key) // \"\"" "$CONFIG")

if [ -z "$IDX" ]; then
  echo "!! No app named '${APP_NAME}' found in ${CONFIG}"
  emit "changed=false"
  exit 1
fi

name=$(yq -r ".[$IDX].name" "$CONFIG")
image=$(yq -r ".[$IDX].image" "$CONFIG")
manifest=$(yq -r ".[$IDX].manifest" "$CONFIG")
image_path=$(yq -r ".[$IDX].image_path" "$CONFIG")
field_type=$(yq -r ".[$IDX].field_type" "$CONFIG")
pattern=$(yq -r ".[$IDX].tag_pattern" "$CONFIG")

if [ "$field_type" != "combined" ] && [ "$field_type" != "tag_only" ]; then
  echo "!! apps.yaml: field_type for '${name}' must be 'combined' or 'tag_only', got '${field_type}'"
  emit "changed=false"
  exit 0
fi

echo "== Checking ${name} (${image}) =="
emit "name=${name}"

if [ ! -f "$manifest" ]; then
  echo "!! Manifest not found: $manifest"
  emit "changed=false"
  exit 0
fi

# Pull the currently pinned image via the path declared in apps.yaml
# for this app (image_path). Plain Deployments and Helm values.yaml
# files use different keys, so the path is per-app config rather than
# hardcoded here.
#
# combined (plain k8s manifest) files can contain multiple --- separated
# documents (e.g. Namespace + Deployment in one file). yq would otherwise
# evaluate the path against every document and print one result per doc,
# joined by "---". select(kind == "Deployment") isolates the one we want.
# tag_only (Helm values.yaml) files have no "kind:" field at all, so that
# filter doesn't apply there — values.yaml is always a single document.
if [ "$field_type" = "combined" ]; then
  full_image=$(yq -r 'select(.kind == "Deployment") | '"${image_path}" "$manifest")
else
  full_image=$(yq -r "${image_path}" "$manifest")
fi

if [ -z "$full_image" ] || [ "$full_image" = "null" ]; then
  echo "!! Could not find ${image_path} in ${manifest}"
  emit "changed=false"
  exit 0
fi

current="${full_image##*:}"   # everything after the last colon
manifest_image="${full_image%:*}"  # everything before the last colon

if [ "$field_type" = "combined" ]; then
  if [ "$manifest_image" != "$image" ]; then
    echo "!! apps.yaml says image is '${image}' but manifest has '${manifest_image}' — check apps.yaml"
    emit "changed=false"
    exit 0
  fi
  if [ "$current" = "latest" ] || [ "$current" = "$full_image" ]; then
    # Either explicitly ":latest", or no colon at all (Docker treats a
    # bare "repo" with no tag as :latest implicitly) — either way,
    # nothing real is pinned yet.
    echo "   current: latest (unpinned)"
    is_pinning=true
  else
    echo "   current: ${current}"
    is_pinning=false
  fi
else
  # tag_only field (Helm values.yaml style): the field IS the tag,
  # no repo prefix to split off or compare.
  current="$full_image"
  if [ "$current" = "latest" ]; then
    echo "   current: latest (unpinned)"
    is_pinning=true
  else
    echo "   current: ${current}"
    is_pinning=false
  fi
fi

# List all tags, keep only ones matching the app's release pattern,
# then sort by version and take the newest.
latest=$(skopeo list-tags "docker://${image}" \
  | yq -r '.Tags[]' \
  | grep -E "${pattern}" \
  | sort -V \
  | tail -n1)

if [ -z "$latest" ]; then
  echo "!! No tags matched pattern '${pattern}' — check the pattern in apps.yaml"
  emit "changed=false"
  exit 0
fi

echo "   latest:  ${latest}"
emit "current=${current}"
emit "latest=${latest}"
emit "pinning=${is_pinning}"

if [ "$current" = "$latest" ]; then
  echo "   Already up to date."
  emit "changed=false"
  exit 0
fi

if [ "$is_pinning" = "true" ]; then
  echo "   Pinning ${image}:latest -> ${image}:${latest}"
else
  echo "   Newer version available: ${current} -> ${latest}"
fi

# Patch the manifest in place via the same yq path used to read it.
# This preserves YAML formatting/comments better than a text-based sed
# replace. field_type also decides whether we need the same
# select(kind == "Deployment") isolation used above when reading.
if [ "$field_type" = "combined" ]; then
  yq -i "(select(.kind == \"Deployment\") | ${image_path}) = \"${image}:${latest}\"" "$manifest"
else
  yq -i "${image_path} = \"${latest}\"" "$manifest"
fi

emit "changed=true"
