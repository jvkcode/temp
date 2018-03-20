#!/bin/bash
#/ Usage: [TMP=path_to_downloaded_packages] [DEBUG=1] patch-manifests.sh [OPTIONS]
#/
#/ This script downloads the latest security updates and then patches the
#/ distro related manifests and dev-package files.
#/
#/ OPTIONS:
#/   -h | --help            Show this message
#/   --dry-run              Download and parse APT repository metadata but do not patch the packages manifest
#/   --patch                Patch the packages manifest
#/   --download-only        Download APT repository metadata
#/   --parse-only           Parse an already downloaded APT repository metadata
#/   --patch-no-download    Parse and patch an already downloaded APT repository metadata
#/
# added by Julia K. to debug from command line
#if [ "x${1}" = "x-d" ] ; then
#  shift
#  set -x
#fi

set -e

MIRROR_MAIN='http://httpredir.debian.org/debian'

#setup sources
DEBSOURCES="
$MIRROR_MAIN/dists/jessie/main/binary-amd64/Packages.gz
$MIRROR_MAIN/dists/jessie-updates/main/binary-amd64/Packages.gz
http://security.debian.org/dists/jessie/updates/main/binary-amd64/Packages.gz
"

#CVE Data json
CVE_DATA="https://security-tracker.debian.org/tracker/data/json"

TMP=${TMP:-$(mktemp -d)}

# added by Julia K.
declare PRG_NAME=${0}
declare -A SEEN_PKG
declare FORMATED_JSON_FILE="$TMP/cve.json.formated"
declare STARTED_TIME=`date +%s`
# maximum run time must be not more than 10 min
declare MAX_TIME=3600
# set max time warning for downloading packages - 7 min
declare MAX_TIME_1=2520
# set max time warning for updating packages - 9 min
declare MAX_TIME_2=3240

red=$(tput -Txterm setaf 1)
reset=$(tput -Txterm sgr0)

# a simple debug Helper
gh_debug(){
  if [ "$DEBUG" = "1" ]; then
    echo "$@"
  fi
}

download_cve_data(){
  gh_debug "downloading CVE json"
  curl -s $CVE_DATA -o "$TMP/cve.json"
}

# added by Julia K.
sort_cve_data(){
  # if file is not created - skip the rest
  [ -f ${TMP}/cve.json ] || return

  # script tested on Python 2.7.3
  # convert cve.json file to sorted one-line format:
  # python-scipy: CVE-2013-4251: <description>
  ./json-decoder.py ${TMP}/cve.json >${FORMATED_JSON_FILE}
}

print_cve_data(){
  package_name="$1"
  package_version="$2"

  if [ ! -f "$TMP/cve.json" ]; then
    return
  fi
  # Determine the source package
  src_package=$(grep -A 10 -e "^Package: $package_name$" "$unzipped_package_file" \
                | grep "Source:" | grep -m 1 -o " .*" | tr -d ' ')
  # If no source package found, the name is the same
  if [ -z "$src_package" ]; then
    src_package=$package_name
  fi

  # Use this as the starting point to implement your solution. If you want to use another
  # language than bash, you can call your script here to retrieve the CVE information.
  # In that case, make sure to pass in the necessary arguments such as the path to the CVE file
  # ($TMP/cve.json).
  # Tracking if a source package has been seen still needs to be implemented
  # in this script, we recommend using a Bash associative array for that.
  
  # added by Julia K.
  # see function sort_cve_data(): create cve.json.formated file
  # get CVE pkg_info info from formated file:
  local f=${FORMATED_JSON_FILE}
  if [ "x${SEEN_PKG[$src_package]}" = "x" ] ; then
    SEEN_PKG[$src_package]=1
    gh_debug "DEBUG: $src_package:"
    grep -wE "^${src_package}:" ${f} | sed -s "s/^$src_package: /* Security Tracker: /g"
  fi
}

# added by Julia K.
count_remaining_time(){
  local cur_time=$(date +%s)
  ellapsed_time=$((${cur_time}-${STARTED_TIME}))
  if [ $ellapsed_time -gt ${1} ] ; then
    return 1
  fi
  return 0
}

# downloads all the packages from defined sources
download_packages(){
  rm -rf "$TMP"
  mkdir -p "$TMP"
  #download all the packages.gz file
  for t in $DEBSOURCES; do
    # added by Julia K. count limited time
    count_remaining_time ${MAX_TIME_1}
    if [ $? -eq 1 ] ; then
      gh_debug "${FUNCNAME}: Ellapsed time: ${MAX_TIME_1} sec"
    fi
    #extract distro name from source. use distro_repo.gz as filename
    distro=$(echo "$t" | awk -F'/' '{print $4 "_" $6}')
    pfile=$distro.gz

    gh_debug "dowloading...$t"

    #download the dist packages
    curl -L -s "$t" -o  "$TMP/$pfile"
  done
  # moved by Julia K.
  #download_cve_data
  #sort_cve_data
}

# Unzips the package file, parses the current manifest files,
# makes comparisons and then patches the file in place
parse_and_patch_packages(){
  downloaded_files=$(find "$TMP" -type f -iname \*.gz)
  gh_debug "$downloaded_files"
  for f in $downloaded_files; do
    gh_debug "handling $f"
    # get directory to process e.g 'manifest-jessie' assumes the downloaded files
    # are in the format distro-repo.gz e.g jessie_jessie-security.gz
    distro=$(echo "$f" | awk -F"$TMP/" '{print $2}' | awk -F'_' '{print $1}')
    dir=manifest
    gh_debug "$dir"
    # extract the dev package distro name (assumes the file is relative to the
    # path of the manifest files)
    patch_files=$(find $dir -type f)
    gh_debug "patch_files in $dir: $patch_files"

    unzipped_package_file=$f.$RANDOM
    gunzip -c "$f" > "$unzipped_package_file"

    # added by Julia K. count limited time
    count_remaining_time ${MAX_TIME_1}
    if [ $? -eq 1 ] ; then
      gh_debug "${FUNCNAME}: Ellapsed time: ${MAX_TIME_1} sec"
    fi

    for m_f in $patch_files; do
      # added by Julia K. count limited time - if less then 1 min left - report
      count_remaining_time ${MAX_TIME_2}
      if [ $? -eq 1 ] ; then
        gh_debug "${FUNCNAME}: Ellapsed time: ${MAX_TIME_2} sec"
      fi

      current_manifest_file="$m_f"

      #parse the current manifest file to get all the package names
      gh_debug  "${red}parsing $current_manifest_file...${reset}"
      current_manifest=$(cat "$current_manifest_file")

      echo "$current_manifest" | while read p; do
        p_name=$(echo "$p" | awk -F'=' '{print $1}')
        c_version=$(echo "$p" | awk -F'=' '{print $2}')

        #handle cases where the package name contains arch e.g pkg:amd64=1.2.3
        strip_arch_name=0
        if [[ $p_name == *":amd64"* ]]; then
          gh_debug -n "stripping arch in package name: $p_name to "
          p_name=$(echo "$p_name" | awk -F ":amd64" '{print $1}')
          strip_arch_name=1
          gh_debug "$p_name"
        fi


        #skipping any package that has a +github version number
        if [[ $c_version == *"+github"* ]]; then
          gh_debug "skipping $p_name since it has an internal github version: $c_version"
          continue
        fi

        #search for an exact match of the package and get surrounding
        #lines(10 to be safe) to get the "Version" string
        u_version=$(grep -A 10 -e "^Package: $p_name$" "$unzipped_package_file" \
                       | grep "Version:" | grep -m 1 -o "[0-9].*") || true

        #skip if the no version of the package is found in the Packages file
        if [ -z "$u_version" ]; then
          gh_debug "$p_name package not in Packages.gz"
          continue
        fi

        gh_debug "$p_name: $c_version $u_version"

        #using dpkg to compare version which takes care of alphanumeric comparisons e.g pkg-2.3.1c-ubuntu1 > pkg-2.3.1a-ubuntu2
        if dpkg --compare-versions "$c_version" lt "$u_version" 2>/dev/null; then
          if [ "$1" = '--patch' ]; then
            echo "*patching ${yellow}$p_name${reset}  $c_version to ${red}$u_version${reset} in $current_manifest_file"
            if [ "$strip_arch_name" = "1" ]; then
              pattern_to_patch="$p_name:amd64=$c_version"
              new_version_patch="$p_name:amd64=$u_version"
            else
              pattern_to_patch="$p_name=$c_version"
              new_version_patch="$p_name=$u_version"
            fi

            #replace new version in-place
            sed -i "s/$pattern_to_patch/$new_version_patch/g" "$current_manifest_file"
          else
            if [ "$strip_arch_name" = "1" ]; then
              echo "*(not patching) upgrade available: $p_name:amd64 $c_version to $u_version in $current_manifest_file"
            else
              echo "*(not patching) upgrade available: $p_name $c_version to $u_version in $current_manifest_file"
            fi
          fi
          print_cve_data $p_name $u_version
        fi
      done
    done
    if [ -n "$unzipped_package_file" ]; then
      rm -rf "$unzipped_package_file"
    fi
  done
}

usage(){
  grep "^#/" <"$0" | cut -c4-
}

main(){
  case "$1" in
    "--dry-run")
      download_packages
      download_cve_data
      sort_cve_data
      # added by Julia K. count limited time
      count_remaining_time ${MAX_TIME_2}
      if [ $? -eq 1 ] ; then
        gh_debug "${FUNCNAME}: Ellapsed time: ${MAX_TIME_2} sec"
      fi
      parse_and_patch_packages
      ;;
    "--patch")
      download_packages

      # added by Julia K. count limited time
      download_cve_data
      sort_cve_data
      count_remaining_time ${MAX_TIME_2}
      if [ $? -eq 1 ] ; then
        gh_debug "${FUNCNAME}: Ellapsed time: ${MAX_TIME_2} sec"
      fi

      parse_and_patch_packages --patch
      ;;
    "--download-only")
      download_packages
      ;;
    "--parse-only")
      # added by Julia K. count limited time
      download_cve_data
      sort_cve_data
      count_remaining_time ${MAX_TIME_1}
      if [ $? -eq 1 ] ; then
        gh_debug "${FUNCNAME}: Ellapsed time: ${MAX_TIME_1} sec"
      fi

      parse_and_patch_packages
      ;;
    "--patch-no-download")
      # added by Julia K. count limited time
      download_cve_data
      sort_cve_data
      count_remaining_time ${MAX_TIME_1}
      if [ $? -eq 1 ] ; then
        gh_debug "${FUNCNAME}: Ellapsed time: ${MAX_TIME_1} sec"
      fi

      parse_and_patch_packages --patch
      ;;
    *)
      usage
    ;;
  esac
}

main "$@"
