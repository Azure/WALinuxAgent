#!/usr/bin/env python

import os
import sys
import imp
import json
import time
import pwd

# waagent has no '.py' therefore create waagent module import manually.
waagent=imp.load_source('waagent','waagent')

from waagent import RunGetOutput,  Run, LoggerInit

"""
Test waagent in azure using azure-cli
Usage:

./azure_test.py --stable_vm_image b4590d9e3ed742e4a1d46e5424aa335e__openSUSE-12.3-v120 --source_disk "http://mystorage.blob.core.windows.net/vhds/my-suse2.vhd" --acct "<storage acct key>" --testname my-osuse --mount_point /mnt/disk --agent_path ../waagent --stable_vm_acct_name MyUserName --stable_vm_acct_pass 'myp455wd' --test_vm_acct_name MyUserName --test_vm_acct_pass 'myp455wd' --azure_location "East US" --part_num 1 --retries 20 --fstype scsi --test_vm_acct_cert /root/.ssh/myCert.pem --stable_vm_acct_cert /root/.ssh/myCert.pem --keep_test_vm_vhd no --teardown_test_vm always --prompt no

azure_test --vm <stable vm name> --testname <testname> [--acct <storage account>]
[--disk <vhd url to use as initial disk image>]
If --disk is specified, use this vhd as starting point,
otherwise use a copy of the stable vm as the starting vhd.

Starting VHD is attached to stable vm and the sources are copied to it.
Spin up a new VM using the VHD.
Loop waiting for provisioned.
If not provisioned:
    Destroy vm and attach the disk to the stable vm.
    Copy the logs to the localhost.
    Destroy all created objects except the starting vhd.
    Exit(1)
If Provosioned:
    Copy the logs to the local host.
    Exit(0)
    
EXAMPLE:

sudo ./azure_test.py --vm my-stable-vm-name --disk "http://mystorageaccount.blob.core.windows.net/myvhds/my-new-os.vhd" --acct mylong-unquoted-starage-account-id --testname my-vm-test --mount_point /my-stablevm-mountpoint --agent_path ../waagent --vm_acct_name root --testvm_acct_name azureuser --testvm_acct_pass 'azureuserpassword' --location "East US" --part_num 2 --retry 20 --fstype bsd --testvm_acct_cert /home/azureuser/.ssh/myCert.pem --keep_vhd "once" --teardown "always" --prompt "no"   
"""

def makeDiskImage(di_name,vhd_url,location,copy=False):
    """
    Create new data disk image of the VHD.  If 'copy'
    is set to True, then create a new VHD in the form of myvhd-di.vhd
    based on the VHD source name.  If 'copy is set to False, re-use the
    vhd.  Returns return code and diskimageVHD path.  Code is 0 on
    success or the azure-cli error code upon error.
    """
    if copy :
        target = os.path.dirname(vhd_url)
        target = target+ '/' + di_name +  '.vhd'
    else :
        target = vhd_url
    cmd='azure vm disk create --json ' + di_name + ' --blob-url ' + target +  ' ' + vhd_url
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log(output)
    waagent.Log(str(code))
    return target,code

def makeVMImage(vmi_name,vhd_url,copy=False):
    """
    Create new VM Image based on Disk Image.
    Returns 0 on success or error code upon error.
    """
    if copy :
        target = os.path.dirname(vhd_url)
        target = target+ '/' + vmi_name +  '.vhd'
    else :
        target = vhd_url
    cmd='azure vm image create --json ' + vmi_name + ' --base-vhd '  + target + ' --os Linux --blob-url ' + vhd_url
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log(str(code))
    waagent.Log(output)
    return code

def makeVM(vm_name,vmi_name,vhd_url,test_name,location,vmuser_name,vmuser_pass,vmuser_cert,copy=False):
    """
    Create new VM from the VM Image.
    Returns 0 on success or error code upon error.
    """
    target=os.path.dirname(vhd_url)
    target = target + '/' + test_name +  '.vhd'
    cmd='azure vm create --json '
    if copy :
        cmd += ' --blob-url "' + target + '"'
    else :
        target=vhd_url
    cmd += ' --location "' + location + '"'
    if os.path.exists(vmuser_cert):
        cmd += ' -t "' + vmuser_cert + '"'
    cmd += ' -e 22 ' + vm_name + ' ' + vmi_name + ' ' + vmuser_name + ' \'' +vmuser_pass + '\''
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log(str(code))
    waagent.Log(output)
    retry=3
    while code !=0 and retry > 0 :
        time.sleep(5)
        code,output=RunGetOutput(cmd,False)
        retry -=1
    return target

def flushDiskImage(di_name,dele=True):
    """
    Delete the VM Image.
    On error we asume the VM disk image is deleted
    """
    cmd='azure vm disk delete --json '
    if dele :
        cmd += '--blob-delete '
    cmd+= di_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def flushVMImage(vmi_name):
    """
    Delete the VM Image.
    Always delete the underlying blob.
    On error we asume the VM image is deleted.
    """
    cmd='azure vm image delete --blob-delete --json ' + vmi_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def flushVM(vm_name,dele=False):
    """
    Delete the VM.
    On error we asume the VM is deleted
    """
    cmd='azure vm delete --json '
    if dele :
        cmd += ' --blob-delete '
    cmd += vm_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code)) 
    waagent.Log(output)
    return output,code


def createStableVMFromVMImage(vm_image,vhd_url):
    """
    Create a new stable vm, provisioned with acct and certificate from
    the VMImage, using the basepath of vhd_url for the new VM's vhd.
    """
    stableVM=testname+'-stable-vm'
    return makeVM(stableVM,vm_image,vhd_url,testname+'-stable',location,stableVMaccount,stableVMpass,stableVMCert,copy=True)
    
def createStableVMFromVHD(vmi_name,vhd_url):
    """
    Create a new stable vm, provisioned with acct and certificate from
    the VHD, using the basepath of vhd_url for the new VM's vhd.
    """
    makeVMImage(vmi_name,vhd_url,False)
    return createStableVMFromVMImage(vmi_name,vhd_url)

def createDiskImageFromStableVMDisk(vm_name):
    """
    Determine the media link for the os disk of the stable vm.
    Create vhd disk image copy.  <vm_name>-<testname>-di
    Return new disk_image_media_path or None on error.
    """
    cmd='azure vm disk list --json'
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    if code:
        print 'Error is ' + str(code)
        waagent.Log( 'Error is ' + str(code))
        return None
    j=json.loads(output)
    source_media_link=None
    for i in j :
        if i.has_key('AttachedTo'):
            if i['AttachedTo']['RoleName'] == vm_name:
                source_media_link=i['MediaLink']
                break
    if not source_media_link:
        print 'Unable to locate OS disk for ' + vm_name 
        waagent.Log( 'Unable to locate OS disk for ' + vm_name )
        return None
    target_name= testname + '-di'
    makeDiskImage(target_name,source_media_link,location,copy=True)
    target_media_link=os.path.dirname(source_media_link) + '/' + target_name + '.vhd'
    return target_media_link

def addDiskImageToVM(vm_name,di_name):
    """
    Attach the disk image to the 'stableVM'.
    Returns the LUN if successful otherwise returns None
    NOTE: azure vm show may return json matching the disk image
    name yet missing the LUN.  When this occurs, the LUN is '0'. 
    """
    cmd='azure vm disk attach --json ' + vm_name + ' ' + di_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log(str(code))
    waagent.Log(output)
    cmd='azure vm show --json ' + vm_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    retries=3
    while code != 0 and retries: 
        retries-=1
        print cmd
        waagent.Log( cmd)
        code,output=RunGetOutput(cmd,False)
        
    if code == 0:
        jsn=json.loads(output)
        for i in jsn['DataDisks']:
            if i['DiskName'] == di_name:
                if 'Lun' in i :
                    return i['Lun']
                else :
                    return u'0'
    return None

    
def dropDiskImageFromVM(vm_name,lun):
    """
    Detach the disk image from the 'stableVM'.
    On Error we assume the disk is no longer attached.
    """
    cmd='azure vm disk detach --json ' + vm_name + ' ' + lun
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def checkVMProvisioned(vm_name):
    cmd='azure vm show --json ' + vm_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    if code ==0 :
        j=json.loads(output)
        print vm_name+' instance status: ', j['InstanceStatus']
        waagent.Log( vm_name+' instance status: ' + j['InstanceStatus'])
        if j['InstanceStatus'] == 'ReadyRole':
            return True, j['InstanceStatus']
    else :
        print 'Error: ' + output , code
        waagent.Log( 'Error: ' + output +  str(code))
    return False, j['InstanceStatus']
        
def updateAgent(agent_path,vm_name,account,cert,disk_mountpoint,mnt_opts,lun,partnum,provisioned_account):
    """
    Copy the agent specified in 'agent' to the Disk
    using the 'stableVM'.
    """
    retries=30
    retry=0
    cmd='uptime'
    while  ssh_command(vm_name,account,cmd)[1] != 0 and  retry < retries :
        time.sleep(10)
        retry+=1
    #setup sudo NOPASSWD
    pss=stableVMpass.replace('$','\$')
    cmd='echo \'' + pss  + '\' > /home/' + account + '/pswd '
    ssh_command(vm_name,account,cmd)
    cmd='echo \'#!/bin/bash\ncat /home/' + account + '/pswd\n\' > /home/' + account + '/pw.sh'
    ssh_command(vm_name,account,cmd)
    cmd='chmod +x /home/' + account + '/pw.sh'
    ssh_command(vm_name,account,cmd)
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A mkdir -p ' + disk_mountpoint
    ssh_command(vm_name,account,cmd)
    retries=3
    # TODO retires here for the mount
    #mount
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A mount ' +mnt_opts + ' ' + lunToDiskName(lun,partnum) + ' ' +disk_mountpoint
    waagent.Log( cmd)
    retry=0
    while  ssh_command(vm_name,account,cmd)[1] not in (0,32) and  retry < retries :
        if retry == 0:
            if 'bsd' in fstype:
                fcmd = "export SUDO_ASKPASS=./pw.sh && sudo -A fsck_ffs -y "
            else :
                fcmd = "export SUDO_ASKPASS=./pw.sh && sudo -A fsck -y "
            fcmd += lunToDiskName(lun,partnum)
            ssh_command(vm_name,account,fcmd)
        time.sleep(2)
        retry+=1

    # remove packaged agent service if present.
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chroot '+ disk_mountpoint+' dpkg -r walinuxagent'
    ssh_command(vm_name,account,cmd)    # remove Ubuntu walinuxagent agent service if present.
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A rm '+ disk_mountpoint+'/etc/default/walinuxagent'
    ssh_command(vm_name,account,cmd)    # remove Ubuntu walinuxagent agent service if present.
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chroot '+ disk_mountpoint+' rpm -e WALinuxAgent'
    ssh_command(vm_name,account,cmd)
    #copy agent
    remote_path='/tmp'
    print 'scp ' + agent_path + ' to ' + vm_name + ' ' + account + ':' + remote_path
    waagent.Log( 'scp ' + agent_path + ' to ' + vm_name + ' ' + account + ':' + remote_path)
    retry=0
    while scp_to_host_command(account,vm_name,remote_path,agent_path)[1] != 0 and retry < retries :
        time.sleep(2)
        retry+=1
    # move agent to /usr/sbin
    cmd= 'export SUDO_ASKPASS=./pw.sh && sudo -A cp ' + remote_path +'/waagent '+ disk_mountpoint+'/usr/sbin/waagent'
    ssh_command(vm_name,account,cmd)
    cmd= 'export SUDO_ASKPASS=./pw.sh && sudo -A chmod 755 '+ disk_mountpoint+'/usr/sbin/waagent'
    ssh_command(vm_name,account,cmd)
    # Fix the password file
    if 'bsd' in fstype:
        cmd='export SUDO_ASKPASS=./pw.sh && sudo -A cp /etc/master.passwd ' + disk_mountpoint + '/etc/master.passwd'
        ssh_command(vm_name,account,cmd)
    else :
        cmd='export SUDO_ASKPASS=./pw.sh && sudo -A cp /etc/passwd ' + disk_mountpoint + '/etc/passwd'
        ssh_command(vm_name,account,cmd)
        cmd='export SUDO_ASKPASS=./pw.sh && sudo -A cp /etc/shadow ' + disk_mountpoint + '/etc/shadow'
        ssh_command(vm_name,account,cmd)
    #remove /var/lib/waagent
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A rm -rf ' + disk_mountpoint + '/var/lib/waagent'
    ssh_command(vm_name,account,cmd)
    #remove /var/log/waagent*
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A rm -rf ' + disk_mountpoint + '/var/log/waagent*'
    ssh_command(vm_name,account,cmd)
    #delete the provisioning user
    if 'bsd' in fstype:
        cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chroot '+ disk_mountpoint+' rmuser -y ' + provisioned_account
        ssh_command(vm_name,account,cmd)
    else :
        cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chroot '+ disk_mountpoint+' userdel -f ' + provisioned_account
        ssh_command(vm_name,account,cmd)
        cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chroot '+ disk_mountpoint+' groupdel ' + provisioned_account
        ssh_command(vm_name,account,cmd)
        cmd='export SUDO_ASKPASS=./pw.sh && sudo -A rm -rf ' + disk_mountpoint + '/home/' + provisioned_account 
        ssh_command(vm_name,account,cmd)
    # install agent
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chroot  '+ disk_mountpoint+'  /usr/sbin/waagent verbose install '
    ssh_command(vm_name,account,cmd)
    cmd="export SUDO_ASKPASS=./pw.sh && sudo -A  sed -i 's/Verbose=n/Verbose=y/' " + disk_mountpoint+"/etc/waagent.conf"
    ssh_command(vm_name,account,cmd)
    #umount
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A umount ' + lunToDiskName(lun,partnum)
    ssh_command(vm_name,account,cmd)
    
def gatherAgentInfo(localpath,vm_name,account,cert,disk_mountpoint,mnt_opts,lun,partnum):
    """
    Copy the /var/lib/waagent, and /var/log directories to
    localhost:localpath.
    """
    retries=30
    retry=0
    cmd='uptime'
    while  ssh_command(vm_name,account,cmd)[1] != 0 and  retry < retries :
        time.sleep(10)
        retry+=1
    #mount
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A mount ' +mnt_opts + ' '  + lunToDiskName(lun,partnum) + ' ' +disk_mountpoint
    print cmd
    waagent.Log( cmd)
    ssh_command(vm_name,account,cmd)
    #copy info
    Run("mkdir -p "+ localpath)
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A mkdir -p /tmp/results'
    ssh_command(vm_name,account,cmd)
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A cp -r  ' + disk_mountpoint + '/var/log /tmp/results/'
    ssh_command(vm_name,account,cmd)
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A cp -r  ' + disk_mountpoint + '/var/lib/waagent /tmp/results/'
    ssh_command(vm_name,account,cmd)
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chmod -R 777 /tmp/results'
    ssh_command(vm_name,account,cmd)
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A chown -R ' + account + '  /tmp/results'
    ssh_command(vm_name,account,cmd)
    scp_from_host_command(account,vm_name,'/tmp/results/*',localpath)
    #umount
    cmd='export SUDO_ASKPASS=./pw.sh && sudo -A umount ' + lunToDiskName(lun,partnum)
    print cmd
    waagent.Log( cmd)
    ssh_command(vm_name,account,cmd)

def lunToDiskName(lun,partnum):
    if 'bsd' in fstype :
        return lunToFreeBSDDiskName(lun,partnum)
    else :
        return lunToScsiDiskName(lun,partnum)

def lunToScsiDiskName(lun,partnum):
    """
    Convert lun to '/dev/sd[chr(ord('c')+lun)]partnum'
    """
    return str('/dev/sd'+chr( (ord('c')+int(lun)) ) +str(partnum))

def lunToFreeBSDDiskName(lun,partnum):
    """
    Convert lun to '/dev/da' + str(lun) + 'p' + partnum
    """
    return '/dev/da'+ str(int(lun))  + 'p' + str(partnum)

def ssh_command(host,account,cmd):
    """
    Wrapper for an ssh operation.
    """
    if stableVMCert == None:
        if not os.path.exists('./pw.sh'):
            with open('./pw.sh','w') as F:
                F.write('#!/bin/bash\ncat ./pswd\n')
            os.system('chmod +x ./pw.sh')
            with open('./pswd','w') as F:
                F.write(stableVMpass)
        req = "export SSH_ASKPASS=./pw.sh && setsid ssh -T -o StrictHostKeyChecking='no' " + account + "@" + host.lower() + ".cloudapp.net \"" + cmd + "\""
    else :
        req = "ssh -t -o StrictHostKeyChecking='no' " + account + "@" + host.lower() + ".cloudapp.net \"" + cmd + "\""
    print req
    waagent.Log(req)
    code,output=RunGetOutput(req,False)
    print output,code
    waagent.Log(str(code))
    waagent.Log(output.encode('ascii','ignore'))
    return output,code

def scp_to_host_command(account,host,remote_path,local_path):
    """
    Wrapper for an scp operation.  Always uses -r.
    Requires key authentication configured.
    """
    req="scp -o StrictHostKeyChecking='no' -r " + local_path + " " + account + "@" + host.lower() + ".cloudapp.net:" + remote_path
    print req
    waagent.Log( req)
    code,output=RunGetOutput(req,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def scp_from_host_command(account,host,remote_path,local_path):
    """
    Wrapper for an scp operation.  Always uses -r.
    Requires key authentication configured.
    """
    req="scp -r " + account + "@" + host.lower() + ".cloudapp.net:" + remote_path + " " + local_path
    print req
    waagent.Log( req)
    code,output=RunGetOutput(req,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def teardown(name):
    diskImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-di'
    while makeDiskImage(diskImageName,sourceVHD,location,True)[1] !=0 :
        time.sleep(20)
    lun=addDiskImageToVM(stableVM,diskImageName)
    while lun == None :
        time.sleep(2)
        lun=addDiskImageToVM(stableVM,diskImageName)
    out,code=flushVM(vmName,True)
    if code != 0 :
        vmDisk=out[out.find('disk with name ')+len('disk with name '):out.find(' is currently in use')]
        while flushDiskImage(vmDisk,True)[1] != 0 :
            time.sleep(5)
    out,code=flushVMImage(vmImageName)
    if code != 0 :
        vmDisk=out[out.find('disk with name ')+len('disk with name '):out.find(' is currently in use')]
        while flushDiskImage(vmDisk,True)[1] != 0 :
            time.sleep(5)
    gatherAgentInfo(localInfo+'/'+name,stableVM,stableVMaccount,stableVMCert,stableVMMountpoint,mountOptions,lun,partNum)
    print 'Logs for ' + vmName + ' copied to ' + localInfo + '/' + name
    waagent.Log( 'Logs for ' + vmName + ' copied to ' + localInfo + '/' + name)
    # detach and delete the disk image
    while dropDiskImageFromVM(stableVM,lun)[1] != 0 :
        time.sleep(2)
    while flushDiskImage(diskImageName,('no' in keep_vhd))[1] != 0 :
        time.sleep(2)
    out,code=flushVM(stableVM,True)
    if code != 0 :
        stableVMDisk=out[out.find('disk with name ')+len('disk with name '):out.find(' is currently in use')]
        while flushDiskImage(stableVMDisk,True)[1] != 0 :
            time.sleep(5)
    if stableVMImageName:
        while flushVMImage(stableVMImageName,True)[1] != 0 :
            time.sleep(2)
    
def doPrompt() :
    if prompt in ('yes','on'):
        raw_input('Press enter to continue:')

if __name__ == '__main__' :
    """
    Create a disk image and attach it to StableVM.
    Copy the current sources to it.
    Detach and delete the disk image container
    Delete the vm image container and the VM.
    Create a vm image container, and the VM.
    Check the VM for provision succedded:
        if so, exit
        if provisioning failed:
            delete the vm, delete the vm image, create a disk image
            from the VM's vhd, attach the disk to the stable VM, copy
            /var/log and /var/lib/waagent to the localhost.
    """
    stableVM=''
    mountOptions=''
    stableVMMountpoint='/mnt/disk' # need to ensure this is created if not existing.
    sourceVHD=''
    location=""
    localAgent='/home/ericg/Public/git_repos/private/WALinuxAgent-Private/waagent_freebsd'
    localInfo='./logs'
    stableVMaccount='' # Need to ensure root permissions for this to work
    stableVMpass=''
    stableVMCert=''
    provisionedVMaccount=''
    provisionedVMpass=''
    provisionedVMCert=''
    account=''
    testname='azuretest'
    partNum=1
    provision_retries=1
    fstype='scsi'
    keep_vhd='no'
    teardown_test_vm='fail'
    teardown_stable_vm='fail'
    prompt = 'yes'
    stable_vm_vhd=None
    stableVMImageName=None
    stable_vm_image=None
    logfile='azure_test.log'
    """
    We need to create a disk image container and attach it to a stable
    vm in order to copy the current sources to it.  Then we detach it,
    delete the disk image container, create a vm image container, and
    the VM. 
    """

    for i in range(len(sys.argv)) :
        if '--stable_vm' == sys.argv[i] : stableVM=sys.argv[i+1]
        elif '--source_disk' == sys.argv[i]: sourceVHD=sys.argv[i+1]
        elif '--storage_acct' == sys.argv[i]: account=sys.argv[i+1]
        elif '--testname' == sys.argv[i] : testname=sys.argv[i+1]
        elif '--stable_vm_mount_point' == sys.argv[i] : stableVMMountpoint=sys.argv[i+1]
        elif '--agent_path' == sys.argv[i] : localAgent=sys.argv[i+1]
        elif '--stable_vm_acct_name' == sys.argv[i] : stableVMaccount=sys.argv[i+1]
        elif '--stable_vm_acct_pass' == sys.argv[i] : stableVMpass=sys.argv[i+1]
        elif '--stable_vm_acct_cert' == sys.argv[i] : stableVMCert=sys.argv[i+1]
        elif '--test_vm_acct_name' == sys.argv[i] : provisionedVMaccount=sys.argv[i+1]
        elif '--test_vm_acct_pass' == sys.argv[i] : provisionedVMpass=sys.argv[i+1]
        elif '--test_vm_acct_cert' == sys.argv[i] : provisionedVMCert=sys.argv[i+1]
        elif '--azure_location' == sys.argv[i] : location=sys.argv[i+1]
        elif '--mount_opts' == sys.argv[i] : mountOptions=sys.argv[i+1]
        elif '--part_num' == sys.argv[i] : partNum=sys.argv[i+1]
        elif '--retries' == sys.argv[i] : provision_retries=int(sys.argv[i+1])
        elif '--fs_type' == sys.argv[i] : fstype=sys.argv[i+1]
        elif '--keep_test_vm_vhd' == sys.argv[i] : keep_vhd=sys.argv[i+1]
        elif '--teardown_test_vm' == sys.argv[i] : teardown_test_vm=sys.argv[i+1]
        elif '--teardown_stable_vm' == sys.argv[i] : teardown_stable_vm=sys.argv[i+1]
        elif '--prompt' == sys.argv[i] : prompt=sys.argv[i+1]
        elif '--stable_vm_image' == sys.argv[i] : stable_vm_image=sys.argv[i+1]
        elif '--stable_vm_vhd' == sys.argv[i] : stable_vm_vhd=sys.argv[i+1]
        elif '--logfile' == sys.argv[i] : logfile=sys.argv[i+1]
        
    LoggerInit(logfile,'')
    waagent.Log("User: "+ pwd.getpwuid(os.geteuid()).pw_name +" Running Command :\n" + reduce(lambda x, y: x+' '+y,sys.argv))

    if len(stableVM) == 0 and not ( stable_vm_image or stable_vm_vhd ):
        print '--vm <stable vm> must be provided unless --stable_vm_image or --stable_vm_vhd'
        waagent.Log( '--vm <stable vm> must be provided!')
        sys.exit(1)
    else:
        if stable_vm_image:
            sourceVHD=createStableVMFromVMImage(stable_vm_image,sourceVHD)
            stableVM=testname+'-stable-vm'
        elif stable_vm_vhd:
            stableVMImageName=testname+'-stable-vi'
            sourceVHD=createStableVMFromVHD(stableVMImageName,stable_vm_vhd)
            stableVM=testname+'-stable-vm'
        p = False
        retries = provision_retries
        while not p and retries > 0:
            p,out = checkVMProvisioned(stableVM)
            if not p:
                if 'Failed' in out or 'Timeout' in out :
                    break
                print  stableVM + ' Not Provisioned - sleeping on retry:' + str( provision_retries - retries ) 
                waagent.Log(  stableVM + ' Not Provisioned - sleeping on retry:' + str( provision_retries - retries ) )
                time.sleep(30)
                retries -= 1
            else :
                print stableVM + ' Provision SUCCEEDED.'
                waagent.Log( stableVM + ' Provision SUCCEEDED.')
    # done creating the stable vm        
    vmImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-vi'
    #flushVMImage(vmImageName)

    # if no disk image name is provided we want to clone the stable vm disk.
    if not sourceVHD:
        sourceVHD=createDiskImageFromStableVMDisk(stableVM)
        if not sourceVHD:
            print 'Errors - unable to create disk image - assuming created'
            waagent.Log( 'Errors - unable to create disk image - assuming created')
        diskImageName=os.path.splitext(os.path.basename(sourceVHD))[0]
    else :
        diskImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-di'
        diskImageVHD,code=makeDiskImage(diskImageName,sourceVHD,location,True)
        if code:
            print 'Error - unable to make ' + diskImageName
            waagent.Log( 'Error - unable to make ' + diskImageName)

    lun=addDiskImageToVM(stableVM,diskImageName)
    while lun == None :
        time.sleep(2)
        lun=addDiskImageToVM(stableVM,diskImageName)

    doPrompt()
    updateAgent(localAgent,stableVM,stableVMaccount,stableVMCert,stableVMMountpoint,mountOptions,lun,partNum,provisionedVMaccount)
    doPrompt()
    #reboot to prevent stale mount bugs
    cmd= 'export SUDO_ASKPASS=./pw.sh && sudo -A reboot'
    ssh_command(stableVM,stableVMaccount,cmd)

    while dropDiskImageFromVM(stableVM,lun)[1] != 0 :
        time.sleep(2)
    while flushDiskImage(diskImageName,False)[1] != 0 :
        time.sleep(2)
    vmImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-vi'
    flushVMImage(vmImageName)
    vmName=testname+'-vm'
    flushVM(vmName)
    makeVMImage(vmImageName,diskImageVHD,True)
    sourceVHD=makeVM(vmName,vmImageName,sourceVHD,testname,location,provisionedVMaccount,provisionedVMpass,provisionedVMCert,True)
    print 'The new source vhd is ' + sourceVHD
    waagent.Log( 'The new source vhd is ' + sourceVHD)
    p = False
    retries = provision_retries
    while not p and retries > 0:
        p,out = checkVMProvisioned(vmName)
        if not p:
            if 'Failed' in out or 'Timeout' in out :
                break
            print  vmName + ' Not Provisioned - sleeping on retry:' + str( provision_retries - retries ) 
            waagent.Log(  vmName + ' Not Provisioned - sleeping on retry:' + str( provision_retries - retries ) )
            time.sleep(30)
        else :
            print vmName + ' Provision SUCCEEDED.'
            waagent.Log( vmName + ' Provision SUCCEEDED.')
            doPrompt()
            if teardown_test_vm in ('success','always'):
                teardown(testname+'_pass')
            sys.exit(0)
        retries -= 1
    
    print vmName + ' Provision FAILED.'
    waagent.Log( vmName + ' Provision FAILED.')
    doPrompt()
    if teardown_test_vm in ('fail','always'):
                teardown(testname+'_fail')
    sys.exit(1)
