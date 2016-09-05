#!/bin/sh
set -v
# local ##### upload this file on "restore config" Menu only !!!
##############################################################################
 #
 # @category "Cgminer 4.9.2 for Bitmain Antminer S9"
 # @package "Mintorro-S9 Firmware"
 # @author Miguel Padilla <miguel.padilla@zwilla.de>
 # @copyright (c) 2016 - Miguel Padilla
 # @link "https://www.mintorro.com"
 #
 # According to our dual licensing model, this program can be used either
 # under the terms of the GNU Affero General Public License, version 3,
 # or under a proprietary license.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 # GNU Affero General Public License for more details.
 #
##############################################################################
#
# vi restoreConfig-sh
# paste this code into
# press "esc" "w" "q"
#
# create the md5 sum at the folder where you compiled the source
#
#  cp cgminer bmminer
#  cp cgminer-api bmminer-api
#  md5sum bmminer-api > bmminer-api.md5
#  md5sum bmminer > bmminer.md5
#
#  review this script, test it on ssh terminal and then save it again with your changes and
#
#  md5sum restoreConfig.sh > restoreConfig.md5
#
#  cp restoreConfig.sh and restoreConfig.md5 to your build root
#
# create the tar
# tar -cf AntminerS9-Update-Bmminer.tar restoreConfig.md5 bmminer.md5 bmminer-api.md5 restoreConfig.sh bmminer-api bmminer
#
# now copy AntminerS9-Update-Bmminer.tar to your computer from where you have access to the frontend of your Antminer S9
#
#  * click on Menu System
#  * click on Menu Upgrade
#  * click on menu "Restore backup"
#  * choose the AntminerS9-Update-Bmminer.tar
#  * click on "upload Archive..."
#
# now the following process will start:
#
#   * uploading AntminerS9-Update-Bmminer.tar
#   * check for old version and delete them
#   * check the md5sum of the files
# 
mkdir -p /config/.old_config

rm -rf /config/.old_config/*
cd /config/

rm -rf /config/bmminer
rm -rf /config/bmminer-api
rm -rf /config/bmminer.md5
rm -rf /config/bmminer-api.md5

for f in restoreConfig.md5 bmminer.md5 bmminer-api.md5 restoreConfig.sh bmminer-api bmminer; do
    if [ -f $f ] ; then
	    cp $f /config/
    fi
done

md5ok1=$(md5sum -c /config/bmminer.md5);
md5ok2=$(md5sum -c /config/bmminer-api.md5);
md5ok3=$(md5sum -c /config/restoreConfig.md5);

if [ "$md5ok1"="bmminer: OK" ] && [ "$md5ok2"="bmminer-api: OK" ] && [ "$md5ok3"="restoreConfig.md5: OK" ] ; then
cp /usr/bin/bmminer /config/bmminer-backup
cp /usr/bin/bmminer-api /config/bmminer-api-backup
rm -- /usr/bin/bmminer
rm -- /usr/bin/bmminer-api
cp /config/bmminer /usr/bin/bmminer
cp /config/bmminer-api /usr/bin/bmminer-api
/etc/init.d/bmminer.sh restart
fi;

cd - >> /dev/null
cp * /config/
sync

# NOTE!!! Not yet tested !!!
