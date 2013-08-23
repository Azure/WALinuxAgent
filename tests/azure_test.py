#!/usr/bin/env python

import os
import sys
import imp
import json
import time
import pwd

# waagent has no '.py' therefore create waagent module import manually.
waagent=imp.load_source('waagent','waagent')

from waagent import RunGetOutput, RunSendStdin, Run, LoggerInit


"""
Test waagent in azure using azure-cli
Usage:

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

sudo ./azure_test.py --vm my-stable-vm-name --disk "http://mystorageaccount.blob.core.windows.net/myvhds/my-new-os.vhd" --acct mylong-unquoted-starage-account-id --testname my-vm-test --mount_point /my-stablevm-mountpoint --agent_path ../waagent --vm_acct_name root --testvm_acct_name azureuser --testvm_acct_pass 'azureuserpassword' --location "East US" --part_num 2 --retry 20 --fstype bsd --testvm_acct_cert /home/azureuser/.ssh/myCert.pem --create "once" --teardown "always" --prompt "no"   
"""

def makeDiskImage(di_name,vhd_url,location,copy=False):
    """
    Create new data disk image lease attached to the VHD.  If 'create'
    is set to True, then create a new VHD in the form of myvhd-di.vhd
    based on the VHD source name.  Determine storage path by dirname
    of vhd_url.  Returns code and diskimageVHD path.
    Returns 0 on success or error code upon error.
    """
    target = os.path.dirname(vhd_url)
    target = target+ '/' + di_name +  '.vhd'
    cmd='azure vm disk create --json ' + di_name
    if copy :
        cmd += ' --blob-url ' + target
    else :
        cmd += ' --location "' + location + '"'
        target=vhd_url
    cmd +=  ' ' + vhd_url
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log(output)
    waagent.Log(str(code))
    return code,target

def makeVMImage(vmi_name,vhd_url,copy=False):
    """
    Create new VM Image based on Disk Image.
    Returns 0 on success or error code upon error.
    """
    target = os.path.dirname(vhd_url)
    target = target + '/'+ vmi_name +  '.vhd'
    cmd='azure vm image create --json ' + vmi_name
    if copy :
        cmd += ' --base-vhd '  + target
    #else :
    #    cmd += ' --location ' +  vhd_url
        
    cmd += ' --os Linux --blob-url ' + vhd_url

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
    target = target + '/' + testname +  '.vhd'
    cmd='azure vm create --json '
    if copy :
        cmd += ' --blob-url "' + target + '"'
    else :
        target=vhd_url
    cmd += ' --location "' + location + '"'
    if os.path.exists(vmuser_cert):
        cmd += ' -t "' + vmuser_cert + '"'
    cmd += ' -e 22 ' + vm_name + ' ' + vmi_name + ' ' + vmuser_name + ' "' +vmuser_pass + '"'
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

def flushDiskImage(di_name):
    """
    Delete the VM Image.
    On error we asume the VM disk image is deleted
    """
    cmd='azure vm disk delete --json ' + di_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def flushVMImage(vmi_name,):
    """
    Delete the VM Image.
    On error we asume the VM image is deleted
    """
    cmd='azure vm image delete --json ' + vmi_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def flushVM(vm_name):
    """
    Delete the VM.
    On error we asume the VM is deleted
    """
    cmd='azure vm delete --json ' + vm_name
    print cmd
    waagent.Log( cmd)
    code,output=RunGetOutput(cmd,False)
    print output,code
    waagent.Log( str(code)) 
    waagent.Log(output)
    return output,code


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
        
def updateAgent(agent_path,vm_name,account,cert,disk_mountpoint,mnt_opts,lun,partnum,provisionedVMaccount):
    """
    Copy the agent specified in 'agent' to the Disk
    using the 'stableVM'.
    """
    retries=3
    # TODO retires here for the mount
    #mount
    cmd='mount ' +mnt_opts + ' ' + lunToDiskName(lun,partnum) + ' ' +disk_mountpoint
    waagent.Log( cmd)
    retry=0
    while  ssh_command(vm_name,account,cmd)[1] not in (0,32) and  retry < retries :
        if retry == 0:
            if 'bsd' in fstype:
                fcmd = "fsck_ffs -y "
            else :
                fcmd = "fsck -y "
            fcmd += lunToDiskName(lun,partnum)
            ssh_command(vm_name,account,fcmd)
        time.sleep(2)
        retry+=1

    #copy agent
    remote_path=disk_mountpoint+'/usr/sbin/waagent'
    print 'scp ' + agent_path + ' to ' + vm_name + ' ' + account + ':' + remote_path
    waagent.Log( 'scp ' + agent_path + ' to ' + vm_name + ' ' + account + ':' + remote_path)
    retry=0
    while scp_to_host_command(account,vm_name,remote_path,agent_path)[1] != 0 and retry < retries :
        time.sleep(2)
        retry+=1
    # Fix the password file
    if 'bsd' in fstype:
        cmd='cp /etc/master.passwd ' + disk_mountpoint + '/etc/master.passwd'
        ssh_command(vm_name,account,cmd)
    else :
        cmd='cp /etc/passwd ' + disk_mountpoint + '/etc/passwd'
        ssh_command(vm_name,account,cmd)
        cmd='cp /etc/shadow ' + disk_mountpoint + '/etc/shadow'
        ssh_command(vm_name,account,cmd)
    #remove /var/lib/waagent
    cmd='rm -rf ' + disk_mountpoint + '/var/lib/waagent'
    ssh_command(vm_name,account,cmd)
    #remove /var/log/waagent*
    cmd='rm -rf ' + disk_mountpoint + '/var/log/waagent*'
    ssh_command(vm_name,account,cmd)
    #delete the provisioning user
    if 'bsd' in fstype:
        cmd='chroot /mnt/disk rmuser -y ' + provisionedVMaccount
        ssh_command(vm_name,account,cmd)
    else :
        cmd='chroot /mnt/disk userdel -f ' + provisionedVMaccount
        ssh_command(vm_name,account,cmd)
        cmd='chroot /mnt/disk groupdel ' + provisionedVMaccount
        ssh_command(vm_name,account,cmd)
        cmd='rm -rf ' + disk_mountpoint + '/home/' + provisionedVMaccount 
        ssh_command(vm_name,account,cmd)
    # install agent
    cmd='chroot  /mnt/disk  /usr/sbin/waagent verbose install '
    ssh_command(vm_name,account,cmd)
    #umount
    cmd='umount ' + lunToDiskName(lun,partnum)
    ssh_command(vm_name,account,cmd)
    
def gatherAgentInfo(localpath,vm_name,account,cert,disk_mountpoint,mnt_opts,lun,partnum):
    """
    Copy the /var/lib/waagent, and /var/log directories to
    localhost:localpath.
    """
    #mount
    cmd='mount ' +mnt_opts + ' '  + lunToDiskName(lun,partnum) + ' ' +disk_mountpoint
    print cmd
    waagent.Log( cmd)
    ssh_command(vm_name,account,cmd)
    #copy info
    Run("mkdir -p "+ localpath)
    scp_from_host_command(account,vm_name,disk_mountpoint+'/var/log',localpath)
    scp_from_host_command(account,vm_name,disk_mountpoint+'/var/lib/waagent',localpath)
    #umount
    cmd='umount ' + lunToDiskName(lun,partnum)
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
    Requires key authentication configured.
    """
    req="ssh " + account + "@" + host.lower() + ".cloudapp.net '" + cmd + "'"
    print req
    waagent.Log( req)
    code,output=RunGetOutput(req,False)
    print output,code
    waagent.Log( str(code))
    waagent.Log(output)
    return output,code

def scp_to_host_command(account,host,remote_path,local_path):
    """
    Wrapper for an scp operation.  Always uses -r.
    Requires key authentication configured.
    """
    req="scp -r " + local_path + " " + account + "@" + host.lower() + ".cloudapp.net:" + remote_path
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
    flushVM(vmName)
    flushVMImage(vmImageName)
    diskImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-di'
    makeDiskImage(diskImageName,sourceVHD,location,(create in 'always'))
    lun=addDiskImageToVM(stableVM,diskImageName)
    gatherAgentInfo(localInfo+'/'+name,stableVM,stableVMaccount,stableVMCert,stableVMMountpoint,mountOptions,lun,partNum)
    print 'Logs for ' + stableVM + ' copied to ' + localInfo + '/' + name
    waagent.Log( 'Logs for ' + stableVM + ' copied to ' + localInfo + '/' + name)
    print 'Data disk ' + diskImageName + ' is attached to ' + stableVM
    waagent.Log( ' disk ' + diskImageName + ' is attached to ' + stableVM)

def doPrompt() :
    if prompt in ('yes','on'):
        k=raw_input('Press enter to continue:')


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
    create='once' 
    teardown_vm='fail'
    prompt = 'yes'
    """
    We need to create a disk image container and attach it to a stable
    vm in order to copy the current sources to it.  Then we detach it,
    delete the disk image container, create a vm image container, and
    the VM.  Check the VM for provision succedded, if so, exit.  If
    provisioning failed, then: delete the vm, delete the vm image,
    create a disk image from the VM's vhd, and attach the disk to the
    stable VM, copy /var/log and /var/lib/waagent to the localhost.
    """

    LoggerInit('azure_test.log','')
    waagent.Log("User: "+ pwd.getpwuid(os.geteuid()).pw_name +"Running Command :\n" + reduce(lambda x, y: x+' '+y,sys.argv))
    for i in range(len(sys.argv)) :
        if '--vm' == sys.argv[i] : stableVM=sys.argv[i+1]
        elif '--disk' == sys.argv[i]: sourceVHD=sys.argv[i+1]
        elif '--acct' == sys.argv[i]: account=sys.argv[i+1]
        elif '--testname' == sys.argv[i] : testname=sys.argv[i+1]
        elif '--mount_point' == sys.argv[i] : stableVMMountpoint=sys.argv[i+1]
        elif '--agent_path' == sys.argv[i] : localAgent=sys.argv[i+1]
        elif '--vm_acct_name' == sys.argv[i] : stableVMaccount=sys.argv[i+1]
        elif '--vm_acct_cert' == sys.argv[i] : stableVMCert=sys.argv[i+1]
        elif '--testvm_acct_name' == sys.argv[i] : provisionedVMaccount=sys.argv[i+1]
        elif '--testvm_acct_pass' == sys.argv[i] : provisionedVMpass=sys.argv[i+1]
        elif '--testvm_acct_cert' == sys.argv[i] : provisionedVMCert=sys.argv[i+1]
        elif '--location' == sys.argv[i] : location=sys.argv[i+1]
        elif '--mnt_opt' == sys.argv[i] : mountOptions=sys.argv[i+1]
        elif '--part_num' == sys.argv[i] : partNum=sys.argv[i+1]
        elif '--retry' == sys.argv[i] : provision_retries=int(sys.argv[i+1])
        elif '--fstype' == sys.argv[i] : fstype=sys.argv[i+1]
        elif '--create' == sys.argv[i] : create=sys.argv[i+1]
        elif '--teardown_vm' == sys.argv[i] : teardown_vm=sys.argv[i+1]
        elif '--prompt' == sys.argv[i] : prompt=sys.argv[i+1]
        
    if len(stableVM) == 0 :
        print '--vm <stable vm> must be provided!'
        waagent.Log( '--vm <stable vm> must be provided!')
        sys.exit(1)

    vmImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-vi'
    flushVMImage(vmImageName)

        
    # if no disk image name is provided we want to clone the stable vm disk.
    if not sourceVHD:
        sourceVHD=createDiskImageFromStableVMDisk(stableVM)
        if not sourceVHD:
            print 'Errors - unable to create disk image - assuming created'
            waagent.Log( 'Errors - unable to create disk image - assuming created')
        diskImageName=os.path.splitext(os.path.basename(sourceVHD))[0]
    else :
        diskImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-di'
        code,diskImageVHD=makeDiskImage(diskImageName,sourceVHD,location,(create in ('always','once')))
        if code:
            print 'Error - unable to make ' + diskImageName
            waagent.Log( 'Error - unable to make ' + diskImageName)
    lun=addDiskImageToVM(stableVM,diskImageName)
    while lun == None :
        time.sleep(2)
        lun=addDiskImageToVM(stableVM,diskImageName)

    updateAgent(localAgent,stableVM,stableVMaccount,stableVMCert,stableVMMountpoint,mountOptions,lun,partNum,provisionedVMaccount)
    doPrompt()
    while dropDiskImageFromVM(stableVM,lun)[1] != 0 :
        time.sleep(2)
    while flushDiskImage(diskImageName)[1] != 0 :
        time.sleep(2)
    vmImageName=os.path.splitext(os.path.basename(sourceVHD))[0]+'-vi'
    flushVMImage(vmImageName)
    vmName=testname+'-vm'
    flushVM(vmName)
    makeVMImage(vmImageName,diskImageVHD,(create in 'always'))
    sourceVHD=makeVM(vmName,vmImageName,sourceVHD,testname,location,provisionedVMaccount,provisionedVMpass,provisionedVMCert,(create in 'always'))
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
            if teardown_vm in ('success','always'):
                teardown(testname+'_pass')
            sys.exit(0)
        retries -= 1
    
    print vmName + ' Provision FAILED.'
    waagent.Log( vmName + ' Provision FAILED.')
    doPrompt()
    if teardown_vm in ('fail','always'):
                teardown(testname+'_fail')
    sys.exit(1)


