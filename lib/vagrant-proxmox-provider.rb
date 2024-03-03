# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

begin
  require "vagrant"
rescue LoadError
  raise "Vagrant is required!"
end

require "guest/guest"
require "vagrant/action/builder"
require "pathname"
require 'rest-client'
require 'retryable'

# Fix wrong header unescaping in RestClient library.
module RestClient
	class Request
		def make_headers user_headers
			unless @cookies.empty?
				user_headers[:cookie] = @cookies.map { |(key, val)| "#{key.to_s}=#{val}" }.sort.join('; ')
			end
			headers = stringify_headers(default_headers).merge(stringify_headers(user_headers))
			headers.merge!(@payload.headers) if @payload
			headers
		end
	end
end
module VagrantProxmoxPlugin
	module Proxmox
		class Config < Vagrant.plugin('2', :config)
			VERSION = "0.0.1"
			attr_accessor :endpoint
			attr_accessor :select_node
			attr_accessor :user_name
			attr_accessor :password
			attr_accessor :vm_type
			attr_accessor :openvz_os_template
			attr_accessor :openvz_template_file
			attr_accessor :replace_openvz_template_file
			attr_accessor :vm_id_range
			attr_accessor :vm_name_prefix
			attr_accessor :vm_memory
			attr_accessor :vm_disk_size
			attr_accessor :vm_storage
			attr_accessor :task_timeout
			attr_accessor :task_status_check_interval
			attr_accessor :ssh_timeout
			attr_accessor :ssh_status_check_interval
			attr_accessor :imgcopy_timeout
			attr_accessor :qemu_os
			attr_accessor :qemu_cores
			attr_accessor :qemu_sockets
			attr_accessor :qemu_template
			attr_accessor :qemu_iso
			attr_accessor :qemu_iso_file
			attr_accessor :replace_qemu_iso_file
			attr_accessor :qemu_disk_size
			attr_accessor :qemu_storage
			attr_accessor :qemu_nic_model
			attr_accessor :qemu_bridge
		
			def initialize
				@endpoint = UNSET_VALUE
				@selected_node = UNSET_VALUE
				@user_name = UNSET_VALUE
				@password = UNSET_VALUE
				@vm_type = UNSET_VALUE
				@openvz_template_file = UNSET_VALUE
				@replace_openvz_template_file = UNSET_VALUE
				@vm_id_range = 900..999
				@vm_name_prefix = 'vagrant_'
				@vm_memory = 512
				@vm_disk_size = '20G'
				@vm_storage = 'local'
				@task_timeout = 60
				@task_status_check_interval = 2
				@ssh_timeout = 60
				@task_status_check_interval = 2
				@ssh_timeout = 60
				@ssh_status_check_interval = 5
				@ssh_timeout = 60
				@ssh_status_check_interval = 5
				@imgcopy_timeout = 120
				@qemu_os = UNSET_VALUE
				@emu = 1
				@emu_sockets = 1
				@qemu_template = UNSET_VALUE
				@qemu_iso = UNSET_VALUE
				@qemu_iso_file = UNSET_VALUE
				@replace_qemu_iso_file = UNSET_VALUE
				@qemu_disk_size = UNSET_VALUE
				@qemu_storage = 'raid'
				@qemu_nic_model = 'e1000'
				@qemu_bridge = 'vmbr0'
			end
		
			def finalize!
				@endpoint = nil if @endpoing == UNSET_VALUE
				@selected_node = nil if @select_node == UNSET_VALUE
				@user_name = nil if @user_name == UNSET_VALUE
				@password = nil if @password == UNSET_VALUE
				@vm_Type = nil if @vm_type == UNSET_VALUE
				@openvz_template_file = nil if @openvz_template_file == UNSET_VALUE
				@openvz_os_template = "local:vztmpl/#{File.basename @openvz_template_file}" if @openvz_template_file
				@openvz_os_template = nil if @openvz_os_template == UNSET_VALUE
				@qemu_template = nil if @qemu_template == UNSET_VALUE
				@qemu_os = nil if @qemu_os == UNSET_VALUE
				@qemu_iso_file = nil if @qemu_iso_file == UNSET_VALUE
				@qemu_iso = "local:iso/#{File.basename @qemu_iso_file}" if @qemu_iso_file
				@qemu_iso = nil if @qemu_iso == UNSET_VALUE
				@qemu_disk_size = nil if @qemu_disk_size == UNSET_VALUE
				@qemu_disk_size = convert_disk_size_to_gigabyte @qemu_disk_size if @qemu_disk_size
				@vm_disk_size = convert_disk_size_to_gigabyte @vm_disk_size if @vm_disk_size
			end
			
			def validate machine
				error = []
				error << I18n.t('vagrant_proxmox.errors.no_endpoint_specified') unless @endpoint
				error << I18n.t('vagrant_proxmox.errors.no_user_name_specified') unless @user_name
				error << I18n.t('vagrant_proxmox.errors.no_password_specified') unless @password
				error << I18n.t('vagrant_proxmox.errors.no_vm_type_specified') unless @vm_type
				if @vm_type == :openvz
					errors << I18.t('vagrant_proxmox.errors.no_openvz_os_template_or_openvz_template_file_specified_for_type_openvz') unless @openvz_os_template || @openvz_template_file
				end
				if @vm_type == :qemu
					if @qemu_template
					else
						error << I18n.t('vagrant_proxmox.errors.no_qemu_os_specified_for_vm_type_qemu') unless @qemu_os
						error << I18n.t('vagrant_proxmox.errors.no_qemu_iso_or_qemu_iso_file_specified_for_vm_type_qemu') unless @qemu_iso | @qemu_iso_file
						error << I18n.t('vagrant_proxmox.errors.no_qemu_disk_size_specified_for_vm_type_qemu') unless @qemu_disk_size
					end
				end
				{'Proxmox Provider' => errors}
			end
			
			private
			def convert_disk_size_to_gigabyte disk_size
				case disk_sizep[-1]
					when 'G'
						disk_size[0..-2]
					else
						disk_size
				end
			end
		end
		module RequiredParameters
			def required keyword
				fail ArgumentError, :missing keyword: #{keyword}", caller
			end
		end
		class Plugin < Vagrant.plugin("2")
    			name "VagrantProxmox"
    			description <<-DESC Plugin for vagant on proxmox.
    			DESC

	    		config(:proxomx, :provider) do
				require_relative 'config'
				Config
			end
			provider(:proxmox, parallel: true) do
				#i dont want logging
				#setup_logging
				setup_i18n
				
				#return the provider
				Provider
			end
			def initialize machine
				@machine = machine
			end
			def action name
				action_method = "action_#{name}"
				return Action.send(action_method) if Action.respond_to?(action_method)
				nil
			end
			
			def state
				env = @machine.action 'read_state'
				
				state_id = env[:machine_state_id]
				
				#Get the short and long description
				short =I18n.t "vagrant_proxmox.states.short_#{state_id}"
				long = I18n.t "vagrant_proxmox.states.long_#{state_id}"
				
				# return the MachineState object
				Vagrant::MachineState.new state_id, short, long
			end
			
			def ssh_info
				env = @machine.action 'read_ssh_info'
				env[:machine_ssh_info]
			end
			
			def to_s
				id = @machine.id.nil? ? 'new' : @machine.id
				"Proxmox (#{id})"
			end
		
			#something about strings
			def self.setup_i18n
				I18n.load_path<< file.expand_path('locales/en.yml', Proxmox.source_root)
				I18n.reload!
			end

			#skipping logging
			
		 	
    			#guest(:proxmoxplugin) do
    			#  Guest
    			#end

    			#guest_capability(:proxmoxplugin, :hello) do
    			#  require_relative 'cap/hello'
    				#  Cap::Hello
   			#end
 		end
		class ProxmoxTaskNotFinished < Exception
		end
		class Connection

			include RequiredParameters

			attr_reader :api_url
			attr_reader :ticket
			attr_reader :csrf_token
			attr_accessor :vm_id_range
			attr_accessor :task_timeout
			attr_accessor :task_status_check_interval
			attr_accessor :imgcopy_timeout

			def initialize api_url, opts = {}
				@api_url = api_url
				@vm_id_range = opts[:vm_id_range] || (900..999)
				@task_timeout = opts[:task_timeout] || 60
				@task_status_check_interval = opts[:task_status_check_interval] || 2
				@imgcopy_timeout = opts[:imgcopy_timeout] || 120
			end

			def login username: required('username'), password: required('password')
				begin
					response = post "/access/ticket", username: username, password: password
					@ticket = response[:data][:ticket]
					@csrf_token = response[:data][:CSRFPreventionToken]
				rescue ApiError::ServerError
					raise ApiError::InvalidCredentials
				rescue => x
					raise ApiError::ConnectionError, x.message
				end
			end

			def get_node_list
				nodelist = get '/nodes'
				nodelist[:data].map { |n| n[:node] }
			end

			def get_vm_state vm_id
				vm_info = get_vm_info vm_id
				if vm_info
					begin
						response = get "/nodes/#{vm_info[:node]}/#{vm_info[:type]}/#{vm_id}/status/current"
						states = {'running' => :running,
											'stopped' => :stopped}
						states[response[:data][:status]]
					rescue ApiError::ServerError
						:not_created
					end
				else
					:not_created
				end
			end

			def wait_for_completion task_response: required('task_response'), timeout_message: required('timeout_message')
				task_upid = task_response[:data]
				timeout = task_timeout
				task_type = /UPID:.*?:.*?:.*?:.*?:(.*)?:.*?:.*?:/.match(task_upid)[1]
				timeout = imgcopy_timeout if task_type == 'imgcopy'
				begin
					retryable(on: VagrantPlugins::Proxmox::ProxmoxTaskNotFinished,
										tries: timeout / task_status_check_interval + 1,
										sleep: task_status_check_interval) do
						exit_status = get_task_exitstatus task_upid
						exit_status.nil? ? raise(VagrantPlugins::Proxmox::ProxmoxTaskNotFinished) : exit_status
					end
				rescue VagrantPlugins::Proxmox::ProxmoxTaskNotFinished
					raise VagrantPlugins::Proxmox::Errors::Timeout.new timeout_message
				end
			end

			def delete_vm vm_id
				vm_info = get_vm_info vm_id
				response = delete "/nodes/#{vm_info[:node]}/#{vm_info[:type]}/#{vm_id}"
				wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.destroy_vm_timeout'
			end

			def create_vm node: required('node'), vm_type: required('node'), params: required('params')
				response = post "/nodes/#{node}/#{vm_type}", params
				wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.create_vm_timeout'
			end

			def clone_vm node: required('node'), vm_type: required('node'), params: required('params')
				vm_id = params[:vmid]
				params.delete(:vmid)
				params.delete(:ostype)
				params.delete(:ide2)
				params.delete(:sata0)
				params.delete(:sockets)
				params.delete(:cores)
				params.delete(:description)
				params.delete(:memory)
				params.delete(:net0)
				response = post "/nodes/#{node}/#{vm_type}/#{vm_id}/clone", params
				wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.create_vm_timeout'
			end

			def config_clone node: required('node'), vm_type: required('node'), params: required('params')
				vm_id = params[:vmid]
				params.delete(:vmid)
				response = post "/nodes/#{node}/#{vm_type}/#{vm_id}/config", params
				wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.create_vm_timeout'
			end

			def get_vm_config node: required('node'), vm_id: required('node'), vm_type: required('node')
				response = get "/nodes/#{node}/#{vm_type}/#{vm_id}/config"
				response = response[:data]
				response.empty? ? raise(VagrantPlugins::Proxmox::Errors::VMConfigError) : response
			end

			def start_vm vm_id
				vm_info = get_vm_info vm_id
				response = post "/nodes/#{vm_info[:node]}/#{vm_info[:type]}/#{vm_id}/status/start", nil
				wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.start_vm_timeout'
			end

			def stop_vm vm_id
				vm_info = get_vm_info vm_id
				response = post "/nodes/#{vm_info[:node]}/#{vm_info[:type]}/#{vm_id}/status/stop", nil
				wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.stop_vm_timeout'
			end

			def shutdown_vm vm_id
				vm_info = get_vm_info vm_id
				response = post "/nodes/#{vm_info[:node]}/#{vm_info[:type]}/#{vm_id}/status/shutdown", nil
				wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.shutdown_vm_timeout'
			end

			def get_free_vm_id
                                # to avoid collisions in multi-vm setups
				sleep (rand(1..3) + 0.1 * rand(0..9))
				response = get "/cluster/resources?type=vm"
				allowed_vm_ids = vm_id_range.to_set
				used_vm_ids = response[:data].map { |vm| vm[:vmid] }
				free_vm_ids = (allowed_vm_ids - used_vm_ids).sort
				free_vm_ids.empty? ? raise(VagrantPlugins::Proxmox::Errors::NoVmIdAvailable) : free_vm_ids.first
			end

			def get_qemu_template_id template
				response = get "/cluster/resources?type=vm"
				found_ids = response[:data].select { |vm| vm[:type] == 'qemu' }.select { |vm| vm[:template] == 1 }.select { |vm| vm[:name] == template }.map { |vm| vm[:vmid] }
				found_ids.empty? ? raise(VagrantPlugins::Proxmox::Errors::NoTemplateAvailable) : found_ids.first
			end

			def upload_file file, content_type: required('content_type'), node: required('node'), storage: required('storage'), replace: false
				delete_file(filename: file, content_type: content_type, node: node, storage: storage) if replace
				unless is_file_in_storage? filename: file, node: node, storage: storage
					res = post "/nodes/#{node}/storage/#{storage}/upload", content: content_type,
										 filename: File.new(file, 'rb'), node: node, storage: storage
					wait_for_completion task_response: res, timeout_message: 'vagrant_proxmox.errors.upload_timeout'
				end
			end

			def delete_file filename: required('filename'), content_type: required('content_type'), node: required('node'), storage: required('storage')
				delete "/nodes/#{node}/storage/#{storage}/content/#{content_type}/#{File.basename filename}"
			end

			def list_storage_files node: required('node'), storage: required('storage')
				res = get "/nodes/#{node}/storage/#{storage}/content"
				res[:data].map { |e| e[:volid] }
			end

			def get_node_ip node, interface
				begin
					response = get "/nodes/#{node}/network/#{interface}"
					response[:data][:address]
				rescue ApiError::ServerError
					:not_created
				end
			end

			# This is called every time to retrieve the node and vm_type, hence on large
			# installations this could be a huge amount of data. Probably an optimization
			# with a buffer for the machine info could be considered.
			private
			def get_vm_info vm_id
				response = get '/cluster/resources?type=vm'
				response[:data]
					.select { |m| m[:id] =~ /^[a-z]*\/#{vm_id}$/ }
					.map { |m| {id: vm_id, type: /^(.*)\/(.*)$/.match(m[:id])[1], node: m[:node]} }
					.first
			end

			private
			def get_task_exitstatus task_upid
				node = /UPID:(.*?):/.match(task_upid)[1]
				response = get "/nodes/#{node}/tasks/#{task_upid}/status"
				response[:data][:exitstatus]
			end

			private
			def get path
				begin
					response = RestClient.get "#{api_url}#{path}", {cookies: {PVEAuthCookie: ticket}}
					JSON.parse response.to_s, symbolize_names: true
				rescue RestClient::NotImplemented
					raise ApiError::NotImplemented
				rescue RestClient::InternalServerError
					raise ApiError::ServerError
				rescue RestClient::Unauthorized
					raise ApiError::UnauthorizedError
				rescue => x
					raise ApiError::ConnectionError, x.message
				end
			end

			private
			def delete path, params = {}
				begin
					response = RestClient.delete "#{api_url}#{path}", headers
					JSON.parse response.to_s, symbolize_names: true
				rescue RestClient::Unauthorized
					raise ApiError::UnauthorizedError
				rescue RestClient::NotImplemented
					raise ApiError::NotImplemented
				rescue RestClient::InternalServerError
					raise ApiError::ServerError
				rescue => x
					raise ApiError::ConnectionError, x.message
				end
			end

			private
			def post path, params = {}
				begin
					response = RestClient.post "#{api_url}#{path}", params, headers
					JSON.parse response.to_s, symbolize_names: true
				rescue RestClient::Unauthorized
					raise ApiError::UnauthorizedError
				rescue RestClient::NotImplemented
					raise ApiError::NotImplemented
				rescue RestClient::InternalServerError
					raise ApiError::ServerError
				rescue => x
					raise ApiError::ConnectionError, x.message
				end
			end

			private
			def headers
				ticket.nil? ? {} : {CSRFPreventionToken: csrf_token, cookies: {PVEAuthCookie: ticket}}
			end

			private
			def is_file_in_storage? filename: required('filename'), node: required('node'), storage: required('storage')
				(list_storage_files node: node, storage: storage).find { |f| f =~ /#{File.basename filename}/ }
			end
		end
		module Action
			include Vagrant::Action::Builtin
			def self.action_read_state
				Vagrant::Action::Builder.new.tap do |b|
					b.use ConfigValidate
					b.use ConnectProxmox
					b.use ReadState
				end
			end
			def self.action_up
				Vagrant::Action::Builder.new.tap do |b|
					b.use ConfigValidate
					b.use ConnectProxmox
					b.use Call, IsCreated do |env1, b1|
						if env1[:result]
							b1.use Call, IsStopped do |env2, b2|
								if env2[:result]
									b2.use Provision
										b2.use StartVm
										b2.use SyncFolders
									else
										b2.use MessageAlreadyRunning
									end
								end
							else
								b1.use GetNodeList
								b1.use SelectNode
								b1.use Provision
								if env1[:machine].provider_config.vm_type == :openvz
									b1.use Call, UploadTemplateFile do |env2, b2|
										if env2[:result] == :ok
											b2.use CreateVm
											b2.use StartVm
											b2.use SyncFolders
										elsif env2[:result] == :file_not_found
											b2.use MessageFileNotFound
										elsif env2[:result] == :server_upload_error
											b2.use MessageUploadServerError
										end
									end
								elsif env1[:machine].provider_config.vm_type == :lxc
									b1.use Call, UploadTemplateFile do |env2, b2|
										if env2[:result] == :ok
											b2.use CreateVm
											b2.use StartVm
											b2.use SyncFolders
										elsif env2[:result] == :file_not_found
											b2.use MessageFileNotFound
										elsif env2[:result] == :server_upload_error
											b2.use MessageUploadServerError
										end
									end
								elsif env1[:machine].provider_config.vm_type == :qemu
									if env1[:machine].provider_config.qemu_iso
										b1.use Call, UploadIsoFile do |env2, b2|
											if env2[:result] == :ok
												b2.use CreateVm
												b2.use StartVm
												b2.use SyncFolders
											elsif env2[:result] == :file_not_found
												b2.use MessageFileNotFound
											elsif env2[:result] == :server_upload_error
												b2.use MessageUploadServerError
											end
										end
									else
										b1.use CloneVm
										b1.use Call, IsCreated do |env2, b2|
											if env2[:result]
												b2.use AdjustForwardedPortParams
												b2.use ConfigClone
												b2.use StartVm
												b2.use SyncFolders
											elsif env2[:result] == :file_not_found
												b2.use MessageFileNotFound
											elsif env2[:result] == :server_upload_error
												b2.use MessageUploadServerError
											end
										end
									end
								end
							end
						end
					end
				end
		
				def self.action_provision
					Vagrant::Action::Builder.new.tap do |b|
						b.use ConfigValidate
						b.use Call, IsCreated do |env1, b1|
							if env1[:result]
								b1.use Call, IsStopped do |env2, b2|
									if env2[:result]
										b2.use MessageNotRunning
									else
										b2.use Provision
										b2.use SyncFolders
									end
								end
							else
								b1.use MessageNotCreated
							end
						end
					end
				end
	
				def self.action_halt
					Vagrant::Action::Builder.new.tap do |b|
						b.use ConfigValidate
						b.use Call, IsCreated do |env1, b1|
							if env1[:result]
								b1.use Call, IsStopped do |env2, b2|
									if env2[:result]
										b2.use MessageAlreadyStopped
									else
										b2.use ConnectProxmox
										b2.use ShutdownVm
									end
								end
							else
								b1.use MessageNotCreated
							end
						end
					end
				end
			
				# This action is called to destroy the remote machine.
				def self.action_destroy
					Vagrant::Action::Builder.new.tap do |b|
						b.use ConfigValidate
						b.use ConnectProxmox
						b.use Call, IsCreated do |env1, b1|
							if env1[:result]
								b1.use Call, ::Vagrant::Action::Builtin::DestroyConfirm do |env2, b2|
									if env2[:result]
										b2.use Call, IsStopped do |env3, b3|
											b3.use ShutdownVm unless env3[:result]
											b3.use DestroyVm
											b3.use ::Vagrant::Action::Builtin::ProvisionerCleanup
											b3.use CleanupAfterDestroy
										end
									else
										b2.use ::VagrantPlugins::ProviderVirtualBox::Action::MessageWillNotDestroy
									end
								end
							else
								b1.use MessageNotCreated
							end
						end
					end
				end
	
				def self.action_read_ssh_info
					Vagrant::Action::Builder.new.tap do |b|
						b.use ConfigValidate
						b.use ConnectProxmox
						b.use GetNodeList
						b.use SelectNode
						b.use AdjustForwardedPortParams
						b.use ReadSSHInfo
					end
				end
	
				def self.action_ssh
					Vagrant::Action::Builder.new.tap do |b|
						b.use ConfigValidate
						b.use Call, IsCreated do |env1, b1|
							if env1[:result]
								b1.use Call, IsStopped do |env2, b2|
									if env2[:result]
										b2.use MessageNotRunning
									else
										b2.use SSHExec
									end
								end
							else
								b1.use MessageNotCreated
							end
						end
					end
				end
				def self.action_ssh_run
					Vagrant::Action::Builder.new.tap do |b|
						b.use ConfigValidate
						b.use Call, IsCreated do |env1, b1|
							if env1[:result]
								b1.use Call, IsStopped do |env2, b2|
									if env2[:result]
										b2.use MessageNotRunning
									else
										b2.use SSHRun
									end
								end
							else
								b1.use MessageNotCreated
							end
						end
					end
				end
			
				action_root = Pathname.new(File.expand_path '../action', __FILE__)
				autoload :ProxmoxAction, action_root.join('proxmox_action')
				autoload :ConnectProxmox, action_root.join('connect_proxmox')
				autoload :GetNodeList, action_root.join('get_node_list')
				autoload :SelectNode, action_root.join('select_node')
				autoload :ReadState, action_root.join('read_state')
				autoload :IsCreated, action_root.join('is_created')
				autoload :IsStopped, action_root.join('is_stopped')
				autoload :MessageAlreadyRunning, action_root.join('message_already_running')
				autoload :MessageAlreadyStopped, action_root.join('message_already_stopped')
				autoload :MessageNotCreated, action_root.join('message_not_created')
				autoload :MessageNotRunning, action_root.join('message_not_running')
				autoload :MessageFileNotFound, action_root.join('message_file_not_found')
				autoload :MessageUploadServerError, action_root.join('message_upload_server_error')
				autoload :CreateVm, action_root.join('create_vm')
				autoload :CloneVm, action_root.join('clone_vm')
				autoload :AdjustForwardedPortParams, action_root.join('adjust_forwarded_port_params')
				autoload :ConfigClone, action_root.join('config_clone')
				autoload :StartVm, action_root.join('start_vm')
				autoload :StopVm, action_root.join('stop_vm')
				autoload :ShutdownVm, action_root.join('shutdown_vm')
				autoload :DestroyVm, action_root.join('destroy_vm')
				autoload :CleanupAfterDestroy, action_root.join('cleanup_after_destroy')
				autoload :ReadSSHInfo, action_root.join('read_ssh_info')
				autoload :SyncFolders, action_root.join('sync_folders')
				autoload :UploadTemplateFile, action_root.join('upload_template_file')
				autoload :UploadIsoFile, action_root.join('upload_iso_file')
			end
			# This action creates a new virtual machine on the Proxmox server and
			# stores its node and vm_id env[:machine].id
			class AdjustForwardedPortParams < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::adjust_forwarded_port_params'
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.adjust_forwarded_port_params')
					config = env[:machine].provider_config
					node = env[:proxmox_selected_node]
					vm_id = nil

					begin
						vm_id = env[:machine].id.split("/").last
						node_ip = env[:proxmox_connection].get_node_ip(node, 'vmbr0')
						env[:machine].config.vm.networks.each do |type, options|
							next if type != :forwarded_port
							if options[:id] == "ssh"
								# Provisioning and vagrant ssh will use this
								# high port of the selected proxmox node
								options[:auto_correct] = false
								options[:host_ip] = node_ip
								options[:host] = sprintf("22%03d", vm_id.to_i).to_i
								env[:machine].config.ssh.host = node_ip
								env[:machine].config.ssh.port = sprintf("22%03d", vm_id.to_i).to_s
								break
							end
						end
					end
					next_action env
				end
			end
			class CleanupAfterDestroy < ProxmoxAction

				def initialize app, env
					@app = app
				end

				def call env
					FileUtils.rm_rf ".vagrant/machines/#{env[:machine].name}/proxmox"
					next_action env
				end

			end
			# This action clones from a qemu template on the Proxmox server and
			# stores its node and vm_id env[:machine].id
			class CloneVm < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::clone_vm'
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.cloning_vm')
					config = env[:machine].provider_config

					node = env[:proxmox_selected_node]
					vm_id = nil
					template_vm_id = nil

					begin
						template_vm_id = connection(env).get_qemu_template_id(config.qemu_template)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMCloneError, proxmox_exit_status: e.message
					end
	
					begin
						vm_id = connection(env).get_free_vm_id
						params = create_params_qemu(config, env, vm_id, template_vm_id)
						exit_status = connection(env).clone_vm node: node, vm_type: config.vm_type, params: params
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMCloneError, proxmox_exit_status: e.message
					end

					env[:machine].id = "#{node}/#{vm_id}"

					env[:ui].info I18n.t('vagrant_proxmox.done')
					next_action env
				end

				private
				def create_params_qemu(config, env, vm_id, template_vm_id)
					# without network, which will added in ConfigClonedVm
					{vmid: template_vm_id,
					 newid: vm_id,
					 name: env[:machine].config.vm.hostname || env[:machine].name.to_s,
					 description: "#{config.vm_name_prefix}#{env[:machine].name}"}
				end

			end
			# This action modifies the configuration of a cloned vm
			# Basically it creates a user network interface with hostfwd for the provisioning
			# and an interface for every public or private interface defined in the Vagrantfile
			class ConfigClone < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::config_clone'
					@node_ip = nil
					@guest_port = nil
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.configuring_vm')
					config = env[:machine].provider_config
					node = env[:proxmox_selected_node]
					vm_id = nil

					begin
						vm_id = env[:machine].id.split("/").last
						@node_ip = connection(env).get_node_ip(node, 'vmbr0') if config.vm_type == :qemu
						@guest_port = sprintf("22%03d", vm_id.to_i).to_s
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMConfigError, proxmox_exit_status: e.message
					end

					begin
						template_config = connection(env).get_vm_config node: node, vm_id: vm_id, vm_type: config.vm_type
						params = create_params_qemu(config, env, vm_id, template_config)
						exit_status = connection(env).config_clone node: node, vm_type: config.vm_type, params: params
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMConfigError, proxmox_exit_status: e.message
					end

					env[:ui].info I18n.t('vagrant_proxmox.done')
					next_action env
				end

				private
				def create_params_qemu(provider_config, env, vm_id, template_config)
					vm_config = env[:machine].config.vm
					params = {
						vmid: vm_id,
						description: "#{provider_config.vm_name_prefix}#{env[:machine].name}",
					}
					# delete existing network interfaces from template
					to_delete = template_config.keys.select{|key| key.to_s.match(/^net/) }
					params[:delete] = to_delete.join(",") if not to_delete.empty?
					# net0 is the provisioning network, derived from forwarded_port
					net_num = 0
					hostname = vm_config.hostname || env[:machine].name
					netdev0 = [
						"type=user",
						"id=net0",
						"hostname=#{hostname}",
						"hostfwd=tcp:#{@node_ip}:#{@guest_port}-:22",	# selected_node's primary ip and port (22000 + vm_id)
					]
					device0 = [
						"#{provider_config.qemu_nic_model}",
						"netdev=net0",
						"bus=pci.0",
						"addr=0x12",					# starting point for network interfaces
						"id=net0",
						"bootindex=299"
					]
					params[:args] = "-netdev " + netdev0.join(",") + " -device " + device0.join(",")
					# now add a network device for every public_network or private_network
					# ip addresses are ignored here, as we can't configure anything inside the qemu vm.
					# at least we can set the predefined mac address and a bridge
					net_num += 1
					vm_config.networks.each do |type, options|
						next if not type.match(/^p.*_network$/)
						nic = provider_config.qemu_nic_model
						nic += "=#{options[:macaddress]}" if options[:macaddress]
						nic += ",bridge=#{options[:bridge]}" if options[:bridge]
						net = 'net' + net_num.to_s
						params[net] = nic
						net_num += 1
					end

					# some more individual settings
					params[:ide2] = "#{provider_config.qemu_iso},media=cdrom" if provider_config.qemu_iso
					params[:sockets] = "#{provider_config.qemu_sockets}".to_i if provider_config.qemu_sockets
					params[:cores] = "#{provider_config.qemu_cores}".to_i if provider_config.qemu_cores
					params[:balloon] = "#{provider_config.vm_memory}".to_i if provider_config.vm_memory and provider_config.vm_memory < template_config[:balloon]
					params[:memory] = "#{provider_config.vm_memory}".to_i if provider_config.vm_memory
					params
				end

			end
			# This action connects to the Proxmox server and stores the
			# connection in env[:proxmox_connection]
			class ConnectProxmox < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::connect_proxmox'
				end

				def call env
					begin
						config = env[:machine].provider_config
						connection = Connection.new config.endpoint,
																				vm_id_range: config.vm_id_range,
																				task_timeout: config.task_timeout,
																				task_status_check_interval: config.task_status_check_interval,
																				imgcopy_timeout: config.imgcopy_timeout
						connection.login username: config.user_name, password: config.password
						env[:proxmox_connection] = connection
					rescue => e
						raise Errors::CommunicationError, error_msg: e.message
					end
					next_action env
				end

			end
			class CreateVm < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::create_vm'
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.creating_vm')
					config = env[:machine].provider_config

					node = env[:proxmox_selected_node]
					vm_id = nil

					begin
						vm_id = connection(env).get_free_vm_id
						params = create_params_openvz(config, env, vm_id) if config.vm_type == :openvz
						params = create_params_lxc(config, env, vm_id) if config.vm_type == :lxc
						params = create_params_qemu(config, env, vm_id) if config.vm_type == :qemu
						exit_status = connection(env).create_vm node: node, vm_type: config.vm_type, params: params
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMCreateError, proxmox_exit_status: e.message
					end

					env[:machine].id = "#{node}/#{vm_id}"

					env[:ui].info I18n.t('vagrant_proxmox.done')
					next_action env
				end

				private
				def create_params_qemu(config, env, vm_id)
					network = "#{config.qemu_nic_model},bridge=#{config.qemu_bridge}"
					network = "#{config.qemu_nic_model}=#{get_machine_macaddress(env)},bridge=#{config.qemu_bridge}" if get_machine_macaddress(env)
					{vmid: vm_id,
					 name: env[:machine].config.vm.hostname || env[:machine].name.to_s,
					 ostype: config.qemu_os,
					 ide2: "#{config.qemu_iso},media=cdrom",
					 sata0: "#{config.qemu_storage}:#{config.qemu_disk_size},format=qcow2",
					 sockets: config.qemu_sockets,
					 cores: config.qemu_cores,
					 memory: config.vm_memory,
					 net0: network,
					 description: "#{config.vm_name_prefix}#{env[:machine].name}"}
				end

				private
				def create_params_openvz(config, env, vm_id)
					{vmid: vm_id,
					 ostemplate: config.openvz_os_template,
					 hostname: env[:machine].config.vm.hostname || env[:machine].name.to_s,
					 password: 'vagrant',
					 memory: config.vm_memory,
					 description: "#{config.vm_name_prefix}#{env[:machine].name}"}
					.tap do |params|
						params[:ip_address] = get_machine_ip_address(env) if get_machine_ip_address(env)
					end
				end
                
                private
				def create_params_lxc(config, env, vm_id)
					{vmid: vm_id,
					 ostemplate: config.openvz_os_template,
					 hostname: env[:machine].config.vm.hostname || env[:machine].name.to_s,
					 password: 'vagrant',
					 storage: "#{config.vm_storage}:#{config.vm_disk_size}",
					 memory: config.vm_memory,
					 description: "#{config.vm_name_prefix}#{env[:machine].name}"}
					.tap do |params|
						params[:net0] = "name=#{get_machine_interface_name(env)},ip=#{get_machine_ip_address(env)}/24,gw=#{get_machine_gw_ip(env)},bridge=#{get_machine_bridge_name(env)}" if get_machine_ip_address(env)
					end
				end
			end
			class CreateVm < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::create_vm'
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.creating_vm')
					config = env[:machine].provider_config

					node = env[:proxmox_selected_node]
					vm_id = nil

					begin
						vm_id = connection(env).get_free_vm_id
						params = create_params_openvz(config, env, vm_id) if config.vm_type == :openvz
						params = create_params_lxc(config, env, vm_id) if config.vm_type == :lxc
						params = create_params_qemu(config, env, vm_id) if config.vm_type == :qemu
						exit_status = connection(env).create_vm node: node, vm_type: config.vm_type, params: params
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMCreateError, proxmox_exit_status: e.message
					end

					env[:machine].id = "#{node}/#{vm_id}"

					env[:ui].info I18n.t('vagrant_proxmox.done')
					next_action env
				end

				private
				def create_params_qemu(config, env, vm_id)
					network = "#{config.qemu_nic_model},bridge=#{config.qemu_bridge}"
					network = "#{config.qemu_nic_model}=#{get_machine_macaddress(env)},bridge=#{config.qemu_bridge}" if get_machine_macaddress(env)
					{vmid: vm_id,
					 name: env[:machine].config.vm.hostname || env[:machine].name.to_s,
					 ostype: config.qemu_os,
					 ide2: "#{config.qemu_iso},media=cdrom",
					 sata0: "#{config.qemu_storage}:#{config.qemu_disk_size},format=qcow2",
					 sockets: config.qemu_sockets,
					 cores: config.qemu_cores,
					 memory: config.vm_memory,
					 net0: network,
					 description: "#{config.vm_name_prefix}#{env[:machine].name}"}
				end

				private
				def create_params_openvz(config, env, vm_id)
					{vmid: vm_id,
					 ostemplate: config.openvz_os_template,
					 hostname: env[:machine].config.vm.hostname || env[:machine].name.to_s,
					 password: 'vagrant',
					 memory: config.vm_memory,
					 description: "#{config.vm_name_prefix}#{env[:machine].name}"}
					.tap do |params|
						params[:ip_address] = get_machine_ip_address(env) if get_machine_ip_address(env)
					end
				end
                
                private
				def create_params_lxc(config, env, vm_id)
					{vmid: vm_id,
					 ostemplate: config.openvz_os_template,
					 hostname: env[:machine].config.vm.hostname || env[:machine].name.to_s,
					 password: 'vagrant',
					 storage: "#{config.vm_storage}:#{config.vm_disk_size}",
					 memory: config.vm_memory,
					 description: "#{config.vm_name_prefix}#{env[:machine].name}"}
					.tap do |params|
						params[:net0] = "name=#{get_machine_interface_name(env)},ip=#{get_machine_ip_address(env)}/24,gw=#{get_machine_gw_ip(env)},bridge=#{get_machine_bridge_name(env)}" if get_machine_ip_address(env)
					end
				end
			end
			# This action destroys the virtual machine env[:machine]
			class DestroyVm < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::destroy_vm'
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.destroying_vm')

					begin
						node, vm_id = env[:machine].id.split '/'
						exit_status = connection(env).delete_vm vm_id
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMDestroyError, proxmox_exit_status: e.message
					end

					env[:ui].info I18n.t('vagrant_proxmox.done')

					next_action env
				end

			end
			# This action gets a list of all the nodes e.g. ['node1', 'node2'] of
			# a Proxmox server cluster and stores it under env[:proxmox_nodes]
			class GetNodeList < ProxmoxAction

				def initialize app, env
					@app = app
				end

				def call env
					begin
						env[:proxmox_nodes] = env[:proxmox_connection].get_node_list
						next_action env
					rescue => e
						raise Errors::CommunicationError, error_msg: e.message
					end
				end

			end
			# This action gets a list of all the nodes e.g. ['node1', 'node2'] of
			# a Proxmox server cluster and stores it under env[:proxmox_nodes]
			class GetNodeList < ProxmoxAction

				def initialize app, env
					@app = app
				end

				def call env
					begin
						env[:proxmox_nodes] = env[:proxmox_connection].get_node_list
						next_action env
					rescue => e
						raise Errors::CommunicationError, error_msg: e.message
					end
				end

			end
			# set env[:result] to :is_created
			class IsCreated < ProxmoxAction

				def initialize app, env
					@app = app
				end

				def call env
					env[:result] = env[:machine].state.id != :not_created
					next_action env
				end

			end
			# set env[:result] to :is_created
			class IsCreated < ProxmoxAction

				def initialize app, env
					@app = app
				end

				def call env
					env[:result] = env[:machine].state.id != :not_created
					next_action env
				end

			end
			class IsStopped < ProxmoxAction

				def initialize app, env
				  @app = app
				end
		
				def call env
					env[:result] = env[:machine].state.id == :stopped
					next_action env
				end
			end
			class MessageAlreadyRunning < ProxmoxAction

				def initialize app, env
					@app = app
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.already_running')
					next_action env
				end

			end
			class MessageAlreadyStopped < ProxmoxAction

				def initialize app, env
					@app = app
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.already_stopped')
					next_action env
				end

			end
			class MessageFileNotFound < ProxmoxAction

				def initialize app, env
					@app = app
				end

 				def call env
					#TODO add file name
					env[:ui].info I18n.t('vagrant_proxmox.errors.file_not_found')
					next_action env
				end

			end
			class MessageNotCreated < ProxmoxAction

				def initialize app, env
					@app = app
				end

 				def call env
					env[:ui].info I18n.t('vagrant_proxmox.not_created')
					next_action env
				end

			end
			class MessageNotRunning < ProxmoxAction

				def initialize app, env
					@app = app
				end

 				def call env
					env[:ui].info I18n.t('vagrant_proxmox.vm_not_running')
					next_action env
				end

			end
			class MessageUploadServerError < ProxmoxAction

				def initialize app, env
					@app = app
				end

 				def call env
					env[:ui].info I18n.t('vagrant_proxmox.errors.server_upload_error')
					next_action env
				end

			end
			class ProxmoxAction

				protected
				def next_action env
					@app.call env
				end

				protected
				def get_machine_ip_address env
					config = env[:machine].provider_config
					if config.vm_type == :qemu
						env[:machine].config.vm.networks.select { |type, _| type == :forwarded_port }.first[1][:host_ip] rescue nil
					else
						env[:machine].config.vm.networks.select { |type, _| type == :public_network }.first[1][:ip] rescue nil
					end
				end
                
                protected
                def get_machine_interface_name env
                    env[:machine].config.vm.networks.select { |type, _| type == :public_network }.first[1][:interface] rescue nil
                end
                
                protected
                def get_machine_bridge_name env
                    env[:machine].config.vm.networks.select { |type, _| type == :public_network }.first[1][:bridge] rescue nil
                end
                
                protected
                def get_machine_gw_ip env
                    env[:machine].config.vm.networks.select { |type, _| type == :public_network }.first[1][:gw] rescue nil
                end

				protected
				def get_machine_macaddress env
					env[:machine].config.vm.networks.select { |type, _| type == :public_network }.first[1][:macaddress] rescue nil
				end

				protected
				def connection env
					env[:proxmox_connection]
				end

			end
			# This action stores the ssh information in env[:machine_ssh_info]
			class ReadSSHInfo < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::read_ssh_info'
				end

				def call env
					env[:machine_ssh_info] = get_machine_ip_address(env).try do |ip_address|
						{host: ip_address, port: env[:machine].config.ssh.guest_port}
					end
					env[:machine_ssh_info]
					next_action env
				end

			end
			# This action reads the state of a Proxmox virtual machine and stores it
			# in env[:machine_state_id].
			class ReadState < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::read_state'
				end

				def call env
					begin
						env[:machine_state_id] =
							if env[:machine].id
								node, vm_id = env[:machine].id.split '/'
								env[:proxmox_connection].get_vm_state vm_id
							else
								:not_created
							end
						next_action env
					rescue => e
						raise Errors::CommunicationError, error_msg: e.message
					end

				end

			end
			# This action reads the state of a Proxmox virtual machine and stores it
			# in env[:machine_state_id].
			class SelectNode < ProxmoxAction

				def initialize app, env
				@app = app
				@logger = Log4r::Logger.new 'vagrant_proxmox::action::select_node'
				end

				def call env
				if env[:machine].provider_config.selected_node != Config::UNSET_VALUE
					if env[:proxmox_nodes].include?(env[:machine].provider_config.selected_node)
					env[:proxmox_selected_node] = env[:machine].provider_config.selected_node
					else
					raise Errors::InvalidNodeError, node: env[:machine].provider_config.selected_node
					end
				else
					env[:proxmox_selected_node] = env[:proxmox_nodes].sample
				end
				next_action env
				end

			end
			# This action shuts down the Proxmox virtual machine in env[:machine]
			class ShutdownVm < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::shutdown_vm'
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.shut_down_vm')
					begin
						node, vm_id = env[:machine].id.split '/'
						exit_status = connection(env).shutdown_vm vm_id
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMShutdownError, proxmox_exit_status: e.message
					end
					env[:ui].info I18n.t('vagrant_proxmox.done')

					next_action env
				end

			end
			# This action starts the Proxmox virtual machine in env[:machine]
			class StartVm < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::start_vm'
				end

				def call env
					env[:ui].info I18n.t('vagrant_proxmox.starting_vm')
					begin
						node, vm_id = env[:machine].id.split '/'
						exit_status = connection(env).start_vm vm_id
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMStartError, proxmox_exit_status: e.message
					end

					env[:ui].info I18n.t('vagrant_proxmox.done')

					env[:ui].info I18n.t('vagrant_proxmox.waiting_for_ssh_connection')

					retryException = Class.new StandardError

					begin
						retryable(on: retryException,
											tries: env[:machine].provider_config.ssh_timeout / env[:machine].provider_config.ssh_status_check_interval + 1,
											sleep: env[:machine].provider_config.ssh_status_check_interval) do
							raise retryException unless env[:interrupted] || env[:machine].communicate.ready?
						end
					rescue retryException
						raise VagrantPlugins::Proxmox::Errors::SSHError
					end

					env[:ui].info I18n.t('vagrant_proxmox.done')

					next_action env
				end

			end
			# This action stops the Proxmox virtual machine in env[:machine]
			class StopVm < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::stop_vm'
				end

				def call env
					begin
						node, vm_id = env[:machine].id.split '/'
						env[:ui].info I18n.t('vagrant_proxmox.stopping_vm')
						exit_status = connection(env).stop_vm vm_id
						exit_status == 'OK' ? exit_status : raise(VagrantPlugins::Proxmox::Errors::ProxmoxTaskFailed, proxmox_exit_status: exit_status)
					rescue StandardError => e
						raise VagrantPlugins::Proxmox::Errors::VMStopError, proxmox_exit_status: e.message
					end

					env[:ui].info I18n.t('vagrant_proxmox.done')

					next_action env
				end

			end
			# This action uses 'rsync' to sync the folders over to the virtual machine.
			class SyncFolders < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::sync_folders'
				end

				def call env
					ssh_info = env[:machine].ssh_info

					env[:machine].config.vm.synced_folders.each do |_, data|
						hostpath = File.expand_path data[:hostpath], env[:root_path]
						guestpath = data[:guestpath]
						next if data[:disabled]

						# Make sure there is a trailing slash on the host path to
						# avoid creating an additional directory with rsync
						hostpath = "#{hostpath}/" if hostpath !~ /\/$/

						env[:ui].info I18n.t('vagrant_proxmox.rsync_folder', hostpath: hostpath, guestpath: guestpath)

						# Create the guest path
						env[:machine].communicate.sudo "mkdir -p '#{guestpath}'"
						env[:machine].communicate.sudo "chown #{ssh_info[:username]} '#{guestpath}'"

						# rsync over to the guest path using the SSH info
						command = [
								'rsync', '--verbose', '--archive', '--compress', '--delete',
								'-e', "ssh -p #{ssh_info[:port]} -i '#{ssh_info[:private_key_path][0]}' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
								hostpath, "#{ssh_info[:username]}@#{ssh_info[:host]}:#{guestpath}"]

						rsync_process = Vagrant::Util::Subprocess.execute *command
						if rsync_process.exit_code != 0
							raise Errors::RsyncError, guestpath: guestpath, hostpath: hostpath, stderr: rsync_process.stderr
						end
					end

					next_action env
				end

			end
			# This action uploads a iso file into the local storage a given node
			class UploadIsoFile < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::iso_file_upload'
				end

				def call env
					env[:result] = :ok
					config = env[:machine].provider_config
					if config.qemu_iso_file
						env[:result] = upload_file env, config.qemu_iso_file, config.replace_qemu_iso_file
					end
					next_action env
				end

				private
				def upload_file env, filename, replace
					if File.exist? filename
						begin
							connection(env).upload_file(filename, content_type: 'iso', node: env[:proxmox_selected_node], storage: 'local', replace: replace)
							:ok
						rescue
							:server_upload_error
						end
					else
						:file_not_found
					end
				end
			end
			# This action uploads a template file into the local storage of a given node
			class UploadTemplateFile < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::template_file_upload'
				end

				def call env
					env[:result] = :ok
					config = env[:machine].provider_config
					if config.openvz_template_file
						env[:result] = upload_file env, config.openvz_template_file, config.replace_openvz_template_file
					end
					next_action env
				end

				private
				def upload_file env, filename, replace
					if File.exist? filename
						begin
							connection(env).upload_file(filename, content_type: 'vztmpl', node: env[:proxmox_selected_node], storage: 'local', replace: replace)
							:ok
						rescue
							:server_upload_error
						end
					else
						:file_not_found
					end
				end
			end
		end
		module Errors
			class VagrantProxmoxError < Vagrant::Error::VagrantError
				error_namespace 'vagrant_proxmox.errors'
			end
			
			class ProxmoxTaskFailed < VagrantProxmoxError
				error_key :proxmox_task_failed
			end
			class ProxmoxTaskFAiled < VagrantProxmoxError
				error_key :communication_error
			end
			class Timeout < VagrantProxmoxError
				error_key :timeout
                        end
			class NoVmIdAcailable < VagrantProxmoxError
				error_key :no_vm_id_available
                        end
			class VMCreateError < VagrantProxmoxError
				error_key :vm_create_error
                        end
			class VMCloneError < VagrantProxmoxError
				error_key :no_vm_id_available
                        end
			class VMCreateError < VagrantProxmoxError
				error_key :vm_create_error
                        end
			class VMCloneError < VagrantProxmoxError
				error_key :vm_clone_error
                        end
			class NoTemplateAvailable < VagrantProxmoxError
				error_key :no_template_available
                        end
			class VMConfigError < VagrantProxmoxError
				error_key :vm_configure_error
			end
			class VMDestroyError < VagrantProxmoxError
				error_key :vm_destroy_error
                        end
			class VMStartError < VagrantProxmoxError
				error_key :vm_start_error
                        end
			class VMStopError < VagrantProxmoxError
				error_key :vm_stop_error
                        end
			class VMShutdownError < VagrantProxmoxError
				error_key :vm_shutdown_error
                        end
			class RsyncError < VagrantProxmoxError
				error_key :rsync_error
                        end
			class SSHError < VagrantProxmoxError
				error_key :ssh_error
			end
			class InvalidNodeError < VagrantProxmoxError
				error_key :invalid_node_error
			end

		end
		module ApiError

			class InvalidCredentials < StandardError
			end

			class ConnectionError < StandardError
			end

			class NotImplemented < StandardError
			end

			class ServerError < StandardError
			end

			class UnauthorizedError < StandardError
			end

		end
	end
end
