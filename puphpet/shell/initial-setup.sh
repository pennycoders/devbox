#!/bin/bash

VAGRANT_CORE_FOLDER=$(echo "$1")

OS=$(/bin/bash "${VAGRANT_CORE_FOLDER}/shell/os-detect.sh" ID)
CODENAME=$(/bin/bash "${VAGRANT_CORE_FOLDER}/shell/os-detect.sh" CODENAME)

if [[ ! -d /.puphpet-stuff ]]; then
    mkdir /.puphpet-stuff

    echo "${VAGRANT_CORE_FOLDER}" > "/.puphpet-stuff/vagrant-core-folder.txt"

    cat "${VAGRANT_CORE_FOLDER}/shell/self-promotion.txt"
    echo "Created directory /.puphpet-stuff"
fi

if [[ ! -f /.puphpet-stuff/initial-setup-repo-update ]]; then
    if [ "${OS}" == 'debian' ] || [ "${OS}" == 'ubuntu' ]; then
        echo "Running initial-setup apt-get update"
        apt-get update
        touch /.puphpet-stuff/initial-setup-repo-update
        echo "Finished running initial-setup apt-get update"
    elif [[ "${OS}" == 'centos' ]]; then
        echo "Running initial-setup yum update"
        yum install centos-release-SCL centos-release-cr wget kernel-devel -y
	    yum remove mysql-* -y
        yum update -y
        echo "Finished running initial-setup yum update"

        echo "Updating/installing ruby"
	    yum install automake autoconf make gcc gcc-c++ patch readline readline-devel zlib zlib-devel libyaml-devel libffi-devel openssl-devel make bzip2 autoconf automake libtool bison iconv-devel ruby ruby-devel -y
	    #gem pristine --all
	    #curl -L get.rvm.io | bash -s stable
	    #source /etc/profile.d/rvm.sh
	    #rvm install 2.1.0 --disable-binary
	    #rvm use 2.1.0 --default
		newRuby=$(ruby --version)
	    #yum install facter hiera
        #gem update --system
	    #gem pristine --all
        #gem update
        gem install json rake bundler haml tilt
        echo "Finished updating to ${newRuby}"

        echo "Installing basic development tools (CentOS)"
        yum groupinstall "Development Tools" -y
        echo "Finished installing basic development tools (CentOS)"
        touch /.puphpet-stuff/initial-setup-repo-update
    fi
fi

if [[ "${OS}" == 'ubuntu' && ("${CODENAME}" == 'lucid' || "${CODENAME}" == 'precise') && ! -f /.puphpet-stuff/ubuntu-required-libraries ]]; then
    echo 'Installing basic curl packages (Ubuntu only)'
    apt-get install -y libcurl3 libcurl4-gnutls-dev
    echo 'Finished installing basic curl packages (Ubuntu only)'
    touch /.puphpet-stuff/ubuntu-required-libraries
fi
