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


###############
### HELPERS ###
###############

function preamble() {
  local confirm=no

  echo -ne "\e[91m"
  echo "THERE IS NO WARRANTY FOR THIS PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW."
  echo "EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER"
  echo "PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY OF ANY KIND, EITHER"
  echo "EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF"
  echo "MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE"
  echo "QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE"
  echo "DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION."
  echo "CHOOSING A WRONG BLOCK DEVICE CAN MAKE YOU LOSE PERSONAL DATA. BE CAREFUL!"
  echo -e "\e[39m"

  echo -n "Continue? (yes/no) "
  read confirm && echo

  if [ "${confirm}" != yes ]; then
    exit_error "Aborted"
  fi
}

function show_usage() {
  echo -e "\e[1mOPTIONS\e[0m" >&2
  echo -e "  \e[1m-s\e[0m \e[4mpath\e[0m" >&2
  echo -e "     Target SD card block device (e.g. /dev/sdb, /dev/mmcblk0)" >&2
  echo -e "     \e[2mDefault: Assisted Block Device Detection\e[0m" >&2
  echo -e "  \e[1m-f\e[0m \e[4mpath\e[0m" >&2
  echo -e "     Debian/YunoHost image file (.img or .img.tar.xz)" >&2
  echo -e "     \e[2mDefault: Automatic download from ${url_base}\e[0m" >&2
  echo -e "  \e[1m-g\e[0m \e[4mpath\e[0m" >&2
  echo -e "     GPG signature file for checking image integrity (.img.tar.xz.asc)" >&2
  echo -e "     \e[2mDefault with -f: Automatically filled if there is a .asc next to the image file, else no image integrity checking\e[0m" >&2
  echo -e "     \e[2mDefault without -f: Automatic download from ${url_base}\e[0m" >&2
  echo -e "  \e[1m-l\e[0m" >&2
  echo -e "     Just scan network to find local IPv4s corresponding to Raspberry Pi" >&2
  echo -e "  \e[1m-d\e[0m" >&2
  echo -e "     Enable debug messages" >&2
  echo -e "  \e[1m-h\e[0m" >&2
  echo -e "     Show this help" >&2
}

function exit_error() {
  local msg=${1}
  local usage=${2}

  if [ ! -z "${msg}" ]; then
    echo -e "\e[31m\e[1m[ERR] $1\e[0m" >&2
  fi

  if [ "${usage}" == usage ]; then
    if [ -z "${msg}" ]; then
      echo -e "\n       \e[7m\e[1m YunoHost On Raspberry - SD Card Installer \e[0m\n"
    else
      echo
    fi

    show_usage
  fi

  exit 1
}

function exit_usage() {
  local msg=${1}

  exit_error "${msg}" usage
}

function exit_normal() {
  exit 0
}

function info() {
  local msg=${1}

  echo -e "\e[32m[INFO] ${msg}\e[0m" >&2
}

function warn() {
  local msg=${1}

  echo -e "\e[93m[WARN] ${msg}\e[0m" >&2
}

function debug() {
  local msg=${1}

  if $opt_debug; then
    echo -e "\e[33m[DEBUG] ${msg}\e[0m" >&2
  fi
}

function confirm_writing() {
  local confirm=

  echo -en "\e[93m\e[1mWARNING:\e[0m Data on ${opt_sdcardpath} will be lost. Confirm? (yes/no) "
  read confirm

  if [ "${confirm}" != yes ]; then
    exit_error "Aborted"
  fi
}

function get_partition_path() {
  local partition_number=${1}
  local partition_path="${opt_sdcardpath}${partition_number}"

  if [[ "${opt_sdcardpath}" =~ /mmcblk[0-9]$ ]]; then
    partition_path="${opt_sdcardpath}p${partition_number}"
  fi

  echo "${partition_path}"
}


##########################
### CHECKING FUNCTIONS ###
##########################

function check_sudo() {
  if ! which sudo &> /dev/null; then
    exit_error "sudo command is required"
  fi

  info "This script needs a sudo access"

  if ! sudo echo &> /dev/null; then
    exit_error "sudo password is required"
  fi
}

function check_bins() {
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

function check_findraspberries_bins() {
  local bins=(arp-scan awk)

  for i in "${bins[@]}"; do
    if ! sudo which "${i}" &> /dev/null; then
      exit_error "${i} command is required"
    fi
  done
}

function check_args() {
  if [[ ! -b "${opt_sdcardpath}" || ! "${opt_sdcardpath}" =~ ^/dev/(sd[a-z]|mmcblk[0-9])$ ]]; then
    exit_usage "-s should be a block device corresponding to your SD card (/dev/sd[a-z]\$ or /dev/mmcblk[0-9]\$)"
  fi

  if [ ! -z "${opt_gpgpath}" ]; then
    if [ ! -r "${opt_gpgpath}" ]; then
      exit_usage "File given to -g cannot be read"
    fi

    if [[ ! "${opt_gpgpath}" =~ \.img\.tar\.xz\.asc$ ]]; then
      exit_usage "Filename given to -g must end with .img.tar.xz.asc"
    fi
  fi

  if [ ! -z "${opt_imgpath}" ]; then
    if [ ! -r "${opt_imgpath}" ]; then
      exit_usage "File given to -f cannot be read"
    fi

    if [[ ! "${opt_imgpath}" =~ \.img(\.tar\.xz)?$ ]]; then
      exit_usage "Filename given to -f must end with .img or .img.tar.xz"
    fi

    if [ -z "${opt_gpgpath}" ]; then
      if [ -r "${opt_imgpath}.asc" ]; then
        info "Local GPG signature file found"
        opt_gpgpath="${opt_imgpath}.asc"
      fi
    else
      if [[ "${opt_imgpath}" =~ \.img$ ]] ; then
        exit_usage "File given to -g cannot be used for checking the file given to -f (not archive version)"
      fi

      if [ "$(basename "${opt_gpgpath}")" != "$(basename "${opt_imgpath}").asc" ] ; then
        exit_usage "Based on filenames, file given to -g seems not correspond to the file given to -f"
      fi
    fi

  fi

}


#################
### FUNCTIONS ###
#################

function cleaning_exit() {
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

function cleaning_ctrlc() {
  echo && cleaning_exit error
  exit 1
}

function find_raspberries() {
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

function autodetect_sdcardpath() {
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
      opt_sdcardpath="/dev/${foundblock}"
    else
      exit_error "Aborted"
    fi
  fi
}

function umount_sdcard() {
  local partitions=$(mount | grep "^${opt_sdcardpath}" | awk '{ print $1 }')

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
    debug "${opt_sdcardpath}* is not mounted"
  fi
}

function download_file() {
  local url=$1
  local dest_dir=$2

  debug "Downloading ${url}"

  if ! (cd "${dest_dir}" && curl -#fOA SdCardInstaller "${url}"); then
    return 1
  fi

  return 0
}

function download_img() {

  local tar_name="yunohost-jessie-latest-sdraspi-stable.img.tar.xz"

  info "Image file: ${tar_name}"

  if ! download_file "${url_base}${tar_name}" "${tmp_dir}"; then
    exit_error "Image download failed"
  fi

  img_path="${tmp_dir}/${tar_name}"
}

function download_gpg() {
  local gpg_name="$(basename "${img_path}").asc"

  debug "GPG signature file: ${gpg_name}"

  if ! download_file "${url_base}${gpg_name}" "${tmp_dir}"; then
    exit_error "GPG signature download failed"
  fi

  gpg_path="${tmp_dir}/${gpg_name}"
}

function check_gpg() {
  debug "Creating GnuPG directory: ${tmp_dir}/.gnupg"

  if ! gpg --homedir "${tmp_dir}/.gnupg" -qq --no-tty --no-verbose --batch --list-keys &> /dev/null; then
    exit_error "Cannot create GnuPG directory"
  fi

  debug "Requesting GPG key ${gpg_key} from HKP server ${gpg_server}"

  if ! gpg --homedir "${tmp_dir}/.gnupg" --keyserver "${gpg_server}" -q --no-tty --no-verbose --batch --keyid-format 0xlong --recv-key "${gpg_key}" &> /dev/null; then
    exit_error "GPG key download failed"
  fi

  if ! gpg --trust-model always --no-options --homedir "${tmp_dir}/.gnupg" -q --no-tty --verify "${gpg_path}" &> /dev/null; then
    exit_error "GPG signature error"
  else
    info "GPG signature successfully verified"
  fi
}

function untar_img() {
  debug "Decompressing ${img_path}"

  tar xf "${img_path}" -C "${tmp_dir}"

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

function install_clear() {
  local partition1=$(get_partition_path 1)

  confirm_writing

  info "Please wait..."

  debug "Raw copying ${img_path} to ${opt_sdcardpath} (dd)"
  sudo dd if="${img_path}" of="${opt_sdcardpath}" bs=1M conv=fsync oflag=nocache,sync &> /dev/null

  debug "Flushing file system buffers"
  sudo sync

  debug "Rereading partition table of ${opt_sdcardpath}"
  sudo partprobe "${opt_sdcardpath}"

  mkdir -p "${files_path}" "${raspi_mountpoint}"

  debug "Mounting ${partition1} on ${raspi_mountpoint}"
  sudo mount "${partition1}" "${raspi_mountpoint}"
}


########################
### GLOBAL VARIABLES ###
########################

url_base=https://build.yunohost.org/
gpg_key=0xCD8F4D648AC0ECC1
gpg_server=keyserver.ubuntu.com
deb_version=jessie
opt_findraspberries=false
opt_debug=false
tmp_dir=$(mktemp -dp . .install-sd.sh_tmpXXXXXX)
raspi_mountpoint="${tmp_dir}/raspi_mountpoint"
files_path="${tmp_dir}/files"
img_path=
loopdev=


##############
### SCRIPT ###
##############

trap cleaning_exit EXIT ERR
trap cleaning_ctrlc INT

while getopts "s:f:g:mc:y:e2ldh" opt; do
  case $opt in
    s) opt_sdcardpath=$OPTARG ;;
    f) opt_imgpath=$OPTARG ;;
    g) opt_gpgpath=$OPTARG ;;
    l) opt_findraspberries=true ;;
    d) opt_debug=true ;;
    h) exit_usage ;;
    \?) exit_usage ;;
  esac
done

if $opt_findraspberries; then
  info "Scanning network to find awake connected Raspberries"

  check_sudo
  check_findraspberries_bins
  find_raspberries

  exit_normal
fi

preamble

if [ -z "${opt_sdcardpath}" ]; then
  info "Option -s was not set, starting Assisted Block Device Detection"
  autodetect_sdcardpath

  if [ ! -z "${opt_sdcardpath}" ]; then
    info "Option -s was set to ${opt_sdcardpath}"
  fi
fi

check_sudo
check_args
check_bins

umount_sdcard

img_path=$opt_imgpath
gpg_path=$opt_gpgpath

if [ -z "${img_path}" ]; then
  info "Downloading Debian/YunoHost image (HTTPS)"
  download_img

  if [ -z "${gpg_path}" ]; then
    info "Downloading GPG signature (HTTPS)"
    download_gpg
  fi
fi

if [ ! -z "${gpg_path}" ]; then
  info "Checking GPG signature"
  check_gpg
fi

if [ -z "${gpg_path}" ]; then
  warn "Not checking image integrity"
fi

if [[ "${img_path}" =~ .img.tar.xz$ ]]; then
  info "Decompressing Debian/YunoHost image"
  untar_img
fi

info "Installing SD card (this could take a few minutes)"
install_clear

info "Done"
