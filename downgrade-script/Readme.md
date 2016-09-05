 vi restoreConfig-sh
 paste this code into
 press "esc" "w" "q"

 create the md5 sum at the folder where you compiled the source

  cp cgminer bmminer
  cp cgminer-api bmminer-api
  md5sum bmminer-api > bmminer-api.md5
  md5sum bmminer > bmminer.md5

  review this script, test it on ssh terminal and then save it again with your changes and

  md5sum restoreConfig.sh > restoreConfig.md5

  cp restoreConfig.sh and restoreConfig.md5 to your build root

 create the tar
 tar -cf AntminerS9-Update-Bmminer.tar restoreConfig.md5 bmminer.md5 bmminer-api.md5 restoreConfig.sh bmminer-api bmminer

 now copy AntminerS9-Update-Bmminer.tar to your computer from where you have access to the frontend of your Antminer S9

  * click on Menu System
  * click on Menu Upgrade
  * click on menu "Restore backup"
  * choose the AntminerS9-Update-Bmminer.tar
  * click on "upload Archive..."

 now the following process will start:

   * uploading AntminerS9-Update-Bmminer.tar
   * check for old version and delete them
   * check the md5sum of the files