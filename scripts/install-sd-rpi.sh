#!/bin/bash

# Raspberry Pi SD Card Installer
# Inspired by :
# LaBriqueInternet SD Card Installer
# Copyright (C) 2015-2016 Julien Vaubourg <julien@vaubourg.com>
# Copyright (C) 2015-2016 Emile Morel <emile@bleuchtang.fr>
# Contribute at https://github.com/labriqueinternet/labriqueinter.net
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -e

########################
### GLOBAL VARIABLES ###
########################

url_base=https://build.yunohost.org/
deb_version=jessie
tmp_dir=$(mktemp -dp . .install-sd.sh_tmpXXXXXX)
raspi_mountpoint="${tmp_dir}/raspi_mountpoint"
files_path="${tmp_dir}/files"
loopdev=

img_name="yunohost-${deb_version}-latest-sdraspi-stable.img"
tar_name="${img_name}.tar.xz"
checksum_name="${tar_name}.sum"

working_dir=$(dirname $0)
img_path="${working_dir}/${img_name}"
tar_path="${working_dir}/${tar_name}"
checksum_path="${working_dir}/${checksum_name}"

opt_findraspberries=false
opt_debug=false
opt_custom_sdcardpath=false
opt_custom_img=false
opt_custom_checksum=false

##############
### SCRIPT ###
##############

function parse_options()
{
    while getopts "s:f:mc:ldh" opt; do
      case $opt in
        s) opt_custom_sdcardpath=true; sdcardpath=$OPTARG ;;
        f) opt_custom_img=true
            if [[ "${OPTARG}" =~ \.img\.tar\.xz$ ]]
            then
                tar_path="$OPTARG" 
                img_path=$(echo $OPTARG | sed 's/\.tar\.xz//g')
            else if [[ "${OPTARG}" =~ \.img$ ]]; 
            then
                img_path="$OPTARG" 
                tar_path="${img_path}.tar.xz"
            else
                exit_error "Option -f must be provided with a file ending with .img or .img.tar.xz"
            fi fi
            ;;
        c) opt_custom_checksum=true; checksum_path=$OPTARG; ;;
        l) opt_findraspberries=true ;;
        d) opt_debug=true ;;
        h) exit_usage ;;
        \?) exit_usage ;;
      esac
    done
}

###############
### HELPERS ###
###############

readonly normal=$(printf '\033[0m')
readonly bold=$(printf '\033[1m')
readonly faint=$(printf '\033[2m')
readonly underline=$(printf '\033[4m')
readonly negative=$(printf '\033[7m')
readonly red=$(printf '\033[31m')
readonly green=$(printf '\033[32m')
readonly orange=$(printf '\033[33m')
readonly yellow=$(printf '\033[93m')
readonly white=$(printf '\033[39m')

function show_usage() 
{
  cat >&2 <<- EOF
  ${bold}OPTIONS${normal}
    ${bold}-s${normal} ${underline}path${normal}
       Target SD card block device (e.g. /dev/sdb, /dev/mmcblk0)
       ${faint}Default: Assisted Block Device Detection${normal}
    ${bold}-f${normal} ${underline}path${normal}
       Debian/YunoHost image file (.img or .img.tar.xz)
       ${faint}Default: Automatic download from ${url_base}${normal}
    ${bold}-c${normal} ${underline}path${normal}
       Checksum file to verify image integrity (.img.tar.xz.sum)
       ${faint}Default with -f: Automatically filled if there is a .sum next to the image file, else no image integrity checking${normal}
       ${faint}Default without -f: Automatic download from ${url_base}${normal}
    ${bold}-l${normal}
       Scan local network to find IPv4s corresponding to Raspberry Pi
    ${bold}-d${normal}
       Enable debug messages
    ${bold}-h${normal}
       Show this help
EOF
}

function preamble() 
{
  local confirm=no

  cat <<- EOF
	$red
	THERE IS NO WARRANTY FOR THIS PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.
	EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER
	PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
	EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE
	QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE
	DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
	CHOOSING A WRONG BLOCK DEVICE CAN MAKE YOU LOSE PERSONAL DATA. BE CAREFUL!
	$white
	
	Continue? (yes/no)
EOF
  
  read confirm && echo

  if [ "${confirm}" != yes ]; then
    exit_error "Aborted"
  fi
}

function exit_error() 
{
  local msg=${1}
  local usage=${2}

  if [ ! -z "${msg}" ]; then
    echo "${red}${bold}[ERR] $1${normal}" >&2
  fi

  if [ "${usage}" == usage ]; then
    if [ -z "${msg}" ]; then
      echo -e "\n       ${negative}${bold} YunoHost On Raspberry - SD Card Installer ${normal}\n"
    else
      echo
    fi

    show_usage
  fi

  exit 1
}

function exit_usage() 
{
  local msg=${1}
  exit_error "${msg}" usage
}

function exit_normal() 
{
  exit 0
}

function info() 
{
  local msg=${1}
  echo "${green}[INFO] ${msg}${normal}" >&2
}

function warn() 
{
  local msg=${1}
  echo -e "${yellow}[WARN] ${msg}${normal}" >&2
}

function debug() 
{
  local msg=${1}

  if $opt_debug; then
    echo -e "${orange}[DEBUG] ${msg}${normal}" >&2
  fi
}

function confirm_writing() 
{
  local confirm

  echo -en "${yellow}${bold}WARNING:${normal} Data on ${sdcardpath} will be lost. Confirm? (yes/no) "
  read confirm

  if [ "${confirm}" != yes ]; then
    exit_error "Aborted"
  fi
}

function get_partition_path() 
{
  local partition_number=${1}
  local partition_path="${sdcardpath}${partition_number}"

  if [[ "${sdcardpath}" =~ /mmcblk[0-9]$ ]]; then
    partition_path="${sdcardpath}p${partition_number}"
  fi

  echo "${partition_path}"
}


##########################
### CHECKING FUNCTIONS ###
##########################

function check_sudo() 
{
  if ! which sudo &> /dev/null; then
    exit_error "sudo command is required"
  fi

  info "This script needs a sudo access"

  if ! sudo echo &> /dev/null; then
    exit_error "sudo password is required"
  fi
}

function check_bins() 
{
  local bins=(curl tar awk mountpoint losetup partprobe)

  if [ ! -z "${opt_gpgpath}" ]; then
    bins+=(gpg)
  fi

  for i in "${bins[@]}"; do
    if ! sudo which "${i}" &> /dev/null; then
      exit_error "${i} command is required"
    fi
  done
}

function check_findraspberries_bins() 
{
  local bins=(arp-scan awk)

  for i in "${bins[@]}"; do
    if ! sudo which "${i}" &> /dev/null; then
      exit_error "${i} command is required"
    fi
  done
}

function check_args() 
{
  if [[ ! -b "${sdcardpath}" || ! "${sdcardpath}" =~ ^/dev/(sd[a-z]|mmcblk[0-9])$ ]]; then
    exit_usage "-s should be a block device corresponding to your SD card (/dev/sd[a-z]\$ or /dev/mmcblk[0-9]\$)"
  fi

  if ${opt_custom_checksum}; then
    if [ ! -r "${checksum_path}" ]; then
      exit_usage "File given to -c cannot be read"
    fi

    if [[ ! "${checksum_path}" =~ \.img\.tar\.xz\.sum$ ]]; then
      exit_usage "Filename given to -c must end with .img.tar.xz.sum"
    fi
  fi

  if ${opt_custom_img}; then
    if [ ! -r "${img_path}" ]; then
      exit_usage "File given to -f cannot be read"
    fi

    if [[ ! "${img_path}" =~ \.img(\.tar\.xz)?$ ]]; then
      exit_usage "Filename given to -f must end with .img or .img.tar.xz"
    fi

    if ! ${opt_custom_checksum}; then
      if [ -r "${img_path}.sum" ]; then
        info "Local checksum file found"
        checksum_path="${img_path}.sum"
      fi
    else
      if [[ "${img_path}" =~ \.img$ ]] ; then
        exit_usage "File given to -c cannot be used for checking the file given to -f (not archive version)"
      fi

      if [ "$(basename "${checksum_path}")" != "$(basename "${img_path}").sum" ] ; then
        exit_usage "Based on filenames, file given to -c seems not correspond to the file given to -f"
      fi
    fi

  fi

}


#################
### FUNCTIONS ###
#################

function cleaning_exit() 
{
  local status=$?
  local error=${1}

  trap - EXIT ERR INT

  if $opt_debug && [ "${status}" -ne 0 -o "${error}" == error ]; then
    debug "There was an error, press Enter for doing cleaning"
    read -s
  fi

  local mountpoints=("${raspi_mountpoint}/boot" "${raspi_mountpoint}" "${files_path}")

  for i in "${mountpoints[@]}"; do
    if mountpoint -q "${i}"; then
      debug "Cleaning: umounting ${i}"
      sudo umount "${i}"
    fi
  done

  if [ ! -z "${loopdev}" ] && sudo losetup "${loopdev}" &> /dev/null; then
    debug "Cleaning: detaching loop device ${loopdev}"
    sudo losetup -d "${loopdev}"
  fi

  if [ -b /dev/mapper/raspi ]; then
    debug "Cleaning: closing /dev/mapper/raspi luks device"
    sudo cryptsetup luksClose raspi
  fi

  if [ -d "${tmp_dir}" ]; then
    debug "Cleaning: removing ${tmp_dir}"
    rm -r "${tmp_dir}"
  fi
}

function cleaning_ctrlc() 
{
  echo && cleaning_exit error
  exit 1
}

function find_raspberries() 
{
  local ips=()
  local addip=
  local addhost=
  local knownhosts=0
  local i=0

  local interfaces=$(sudo ip link show up | awk -F: '/state UP/ { print $2 }')

  if [ -z "${interfaces}" ]; then
    exit_error "No enabled ethernet interface found on this computer"
  fi

  debug "Interfaces found: $(echo $interfaces)"

  for i in $interfaces; do
    ips+=($(sudo arp-scan -l --interface="${i}" | grep -P '\tb8:27:eb' | awk '{ print $1 }'))
  done

  if [ -z "${ips}" ]; then
    exit_error "No Raspberries found on the network :("
  fi

  echo -e "\nRaspberries found on the network:\n"

  for ip in "${ips[@]}"; do
    i=$(( i + 1 ))

    knownhost=$(awk "/^$ip/ { print \$2 }" /etc/hosts | head -n1)

    if [ -z "${knownhost}" ]; then
      knownhost=$ip
    else
      (( knownhosts++ )) || true
    fi

    echo -e "  ${i}. YunoHost Admin:\thttps://${knownhost}"
    echo -e "     SSH Access:\tssh root@${knownhost}"
  done

  if [ "${knownhosts}" -ne "${#ips[@]}" ]; then
    echo -n "Select an IP to add to your hosts file (or just press Enter): "
    read addip

    if [ -z "${addip}" ]; then
      exit_normal
    fi

    if [[ "${addip}" =~ ^[0-9]+$ ]]; then
      addip=${ips[$(( addip - 1 ))]}

      if [ -z "${addip}" ]; then
        exit_error "IP index not found"
      fi
    fi

    if [[ ! "${addip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      exit_error "This is not an IPv4 nor an IP index"
    fi

    echo -en "Choose a host name for this IP: "
    read addhost

    echo -e "${addip}\t${addhost}" | sudo tee -a /etc/hosts > /dev/null

    info "IP successfully added to your hosts file"

    echo -e "\n  YunoHost Admin:\thttps://${addhost}"
    echo -e "  SSH Access:\t\tssh root@${addhost}"

#  elif [ "${knownhosts}" -eq 1 ]; then
#    echo "% ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@${knownhost} 2> /dev/null"
#    echo "Press Enter to execute (or Ctrl-C to arbort)"
#    read
#
#    echo "Default Password: raspi"
#    ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "root@${knownhost}" 2> /dev/null
#    exit_normal
  fi
}

function autodetect_sdcardpath() 
{
  echo -n "1. Please, remove the target SD card from your computer if present, then press Enter"
  read -s && echo
  sleep 1

  local blocks1=$(ls -1 /sys/block/)

  debug "Block devices found: $(echo $blocks1)"

  echo -n "2. Please, plug the target SD card into your computer (and don't touch to other devices), then press Enter"
  read -s && echo
  sleep 2

  local blocks2=$(ls -1 /sys/block/)
  local foundblock=;
  local confirm=no;

  debug "Block devices found: $(echo $blocks2)"

  for i in $blocks2; do
    if ! (echo ' '${blocks1}' ' | grep -q " ${i} ") && [ -b "/dev/${i}" ]; then
      if [ ! -z "${foundblock}" ]; then
        debug "Block devices ${foundblock} and ${i} was found"
        exit_error "Assisted Block Device Detection failed: more than 1 new block device found"
      fi

      foundblock="${i}"
    fi
  done

  if [ -z "${foundblock}" ]; then
    exit_error "Assisted Block Device Detection failed: no new block device found"
  else
    echo -en "\nBlock device /dev/${foundblock} found. Use it as your SD card block device? (yes/no) "
    read confirm

    if [ "${confirm}" == yes ]; then
      sdcardpath="/dev/${foundblock}"
    else
      exit_error "Aborted"
    fi
  fi
}

function umount_sdcard() 
{
  local partitions=$(mount | grep "^${sdcardpath}" | awk '{ print $1 }')

  if [ ! -z "${partitions}" ]; then
     IFS=$'\n'

     info "Unmounting SD card partitions"

     for i in ${partitions}; do
      debug "Unmounting ${i}"

      if ! sudo umount -A "${i}" &> /dev/null; then
        exit_error "Umount of ${i} failed"
      fi
    done
  else
    debug "${sdcardpath}* is not mounted"
  fi
}

function download_file() 
{

  local url=$1
  local dest_dir=$2

  debug "Downloading ${url}"

  if ! (cd "${dest_dir}" && curl -#fOA SdCardInstaller "${url}"); then
    return 1
  fi

  return 0
}

function download_img() 
{

  debug "Image file: ${tar_name}"

  if [ -e ${tar_path} ]
  then
      info "Image archive file already present, verifying checksum..."
      if check_checksum
      then
        info "Checksum matched ! No need to redownload image."
        return 0
      else
        info "Checksum mismatch. Redownloading image."
      fi
  fi


  if ! download_file "${url_base}${tar_name}" "${working_dir}"; then
    exit_error "Image download failed"
  fi

}

function download_checksum() 
{

  debug "Checksum file: ${checksum_name}"

  if ! download_file "${url_base}${checksum_name}" "${working_dir}"; then
    exit_error "Checksum download failed"
  fi
}

function check_checksum() 
{
    # TODO
    local sum_to_find=$(cat ${checksum_path} | awk '{print $1}')
    local sum_computed=$(sha512sum ${tar_path} | awk '{print $1}')
    if [ "${sum_to_find}" == "${sum_computed}" ]
    then
        return 0
    else
        return 1
    fi
}

function untar_img() 
{
  debug "Decompressing ${tar_path}"

  tar xf "${tar_path}" -C "${tmp_dir}"

  # Should not have more than 1 line, but, you know...
  img_path=$(find "${tmp_dir}" -name '*.img' | head -n1)

  debug "Debian/YunoHost image is ${img_path}"

  if [ ! -r "${img_path}" ]; then
    exit_error "Decompressed image file cannot be read"
  fi
}


######################
### CORE FUNCTIONS ###
######################

function install_clear() 
{
  local partition1=$(get_partition_path 1)

  confirm_writing

  info "Please wait..."

  debug "Raw copying ${img_path} to ${sdcardpath} (dd)"
  sudo dd if="${img_path}" of="${sdcardpath}" bs=1M conv=fsync oflag=nocache,sync &> /dev/null

  debug "Flushing file system buffers"
  sudo sync

  debug "Rereading partition table of ${sdcardpath}"
  sudo partprobe "${sdcardpath}"

  mkdir -p "${files_path}" "${raspi_mountpoint}"

  debug "Mounting ${partition1} on ${raspi_mountpoint}"
  sudo mount "${partition1}" "${raspi_mountpoint}"
}

function main()
{
    trap cleaning_exit EXIT ERR
    trap cleaning_ctrlc INT

    parse_options "$@"

    if ${opt_findraspberries}; then
      info "Scanning network to find awake connected Raspberries"

      check_sudo
      check_findraspberries_bins
      find_raspberries

      exit_normal
    fi

    preamble

    if ! ${opt_custom_sdcardpath}; then
      info "Option -s was not set, starting Assisted Block Device Detection"
      autodetect_sdcardpath

      if [ ! -z "${sdcardpath}" ]; then
        info "SD card path was set to ${sdcardpath}"
      fi
    fi

    check_sudo
    check_args
    check_bins

    umount_sdcard

    if ! ${opt_custom_img}; then
      if ! ${opt_custom_checksum}; then
        info "Downloading checksum (HTTPS)"
        download_checksum
      fi

      info "Downloading Debian/YunoHost image (HTTPS)"
      download_img
    fi

    if [ -z "${checksum_path}" ]; then
        warn "Not checking image integrity"
    else
        info "Verifying image integrity"
        check_checksum
    fi

    info "Decompressing Debian/YunoHost image"
    untar_img

    info "Installing SD card (this could take a few minutes)"
    install_clear

    info "Done"
}

main "$@"
