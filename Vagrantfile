# Vagrant environment for the DAVINCI prototype.
# It builds an Ubuntu 22.04 virtual machine, installs every dependency through
# the Ansible playbook in provisioning/playbook.yml, and forwards the service
# and platform ports to the host so you can reach DAVINCI from your own browser or
# curl. Run "vagrant up" in this directory to create it.

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "davinci"

  # Expose the three DAVINCI services and the attested platform on the host.
  config.vm.network "forwarded_port", guest: 3030, host: 3030  # Attestation Manager
  config.vm.network "forwarded_port", guest: 3031, host: 3031  # Verifier
  config.vm.network "forwarded_port", guest: 3032, host: 3032  # Privacy Control Engine
  config.vm.network "forwarded_port", guest: 4000, host: 4000  # Platform controller
  config.vm.network "forwarded_port", guest: 4010, host: 4010  # MRAL TPM collector
  config.vm.network "forwarded_port", guest: 4020, host: 4020  # MRAL OP-TEE collector

  config.vm.provider "virtualbox" do |vb|
    vb.name = "davinci"
    # The platform image compiles a kernel and firmware, and the emulated
    # Arm platform itself needs ~1 GiB.
    vb.memory = 6144
    vb.cpus = 4
  end

  # The whole repository is mounted inside the VM at /vagrant.
  # ansible_local installs Ansible in the guest and runs the playbook there,
  # so you do not need Ansible on your host.
  config.vm.provision "ansible_local" do |ansible|
    ansible.playbook = "provisioning/playbook.yml"
  end
end
