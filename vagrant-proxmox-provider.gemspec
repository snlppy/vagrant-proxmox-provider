# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  # TODO: rename name, author, email, description, summary,
  # license, and homepage
  gem.name          = "vagrant-proxmox-provider"
  gem.version       = File.read('VERSION').chop
  gem.authors       = ["snlppy"]
  gem.email         = ["blank"]
  gem.description   = "vagrant plugin for proxmox provisioner"
  gem.summary       = "Vagrant plugin for proxmox"
  gem.license       = 'MIT'
  gem.homepage      = "https://github.com/hashicorp/vagrant-guest-plugin-skeleton-ruby"

  gem.add_development_dependency "rake", "~> 13.0"
  gem.add_development_dependency "rspec", "~> 3.5.0"

  #gem.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features|testdrive)/}) }
  gem.files = Dir.glob('lib/**/*rb') + Dir.glob('locales/**/*.yml')
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.require_paths = ["lib"]
end
