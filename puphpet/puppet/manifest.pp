# Begin Server manifest

if $server_values == undef {
  $server_values = hiera('server', false)
}

# Ensure the time is accurate, reducing the possibilities of apt repositories
# failing for invalid certificates
include '::ntp'

Exec {
  path => [
    '/usr/local/bin/',
    '/bin/',
    '/sbin/',
    '/usr/bin/',
    '/usr/sbin/']
}

group { 'puppet': ensure => present }

group { 'www-data': ensure => present }

user { $::ssh_username:
  shell  => '/bin/bash',
  home   => "/home/${::ssh_username}",
  ensure => present
}

user { [
  'apache',
  'nginx',
  'httpd',
  'www-data']:
  shell   => '/bin/bash',
  ensure  => present,
  groups  => 'www-data',
  require => Group['www-data']
}

file { "/home/${::ssh_username}":
  ensure => directory,
  owner  => $::ssh_username,
}

# copy dot files to ssh user's home directory
exec { 'dotfiles':
  cwd     => "/home/${::ssh_username}",
  command => "cp -r /vagrant/puphpet/files/dot/.[a-zA-Z0-9]* /home/${::ssh_username}/ && chown -R ${::ssh_username} /home/${::ssh_username}/.[a-zA-Z0-9]* && cp -r /vagrant/puphpet/files/dot/.[a-zA-Z0-9]* /root/",
  onlyif  => 'test -d /vagrant/puphpet/files/dot',
  returns => [
    0,
    1],
  require => User[$::ssh_username]
}

# Firewall configuration manifest
# Purge all the existing firewall rules

resources { "firewall": purge => true }

class pre_firewall {
}

class post_firewall {
}

Firewall {
  before  => Class['::post_firewall'],
  require => Class['::pre_firewall'],
}

class { [
  'pre_firewall',
  'post_firewall']:
}

class { 'firewall':
  ensure => running
}

$firewall_values = hiera('firewall', false)

if is_hash($firewall_values['rules']) and count($firewall_values['rules']) > 0 and $firewall_values['setup'] == 1 {
  create_resources(firewall, $firewall_values['rules'])
}

case $::osfamily {
  # debian, ubuntu
  'debian' : {
    class { 'apt': }

    Class['::apt::update'] -> Package <| title != 'python-software-properties' and title != 'software-properties-common' |>

    ensure_packages(['augeas-tools'])
  }
  # redhat, centos
  'redhat' : {
    class { 'yum': extrarepo => ['epel'] }
    $customRepos = hiera('custom_repos', false)

    if is_hash($customRepos) and count($customRepos) > 0 {
      create_resources(yum::managed_yumrepo, $customRepos)
    }

    class { 'yum::repo::rpmforge':
    }

    class { 'yum::repo::repoforgeextras':
    }

    Class['::yum'] -> Yum::Managed_yumrepo <| |> -> Package <| |>

    if defined(Package['git']) == false {
      package { 'git':
        ensure  => latest,
        require => Class['yum::repo::repoforgeextras']
      }
    }

    exec { 'bash_git':
      cwd     => "/home/${::ssh_username}",
      command => "curl https://raw.github.com/git/git/master/contrib/completion/git-prompt.sh > /home/${::ssh_username}/.bash_git",
      creates => "/home/${::ssh_username}/.bash_git"
    }

    exec { 'bash_git for root':
      cwd     => '/root',
      command => "cp /home/${::ssh_username}/.bash_git /root/.bash_git",
      creates => '/root/.bash_git',
      require => Exec['bash_git']
    }

    file_line { 'link ~/.bash_git':
      ensure  => present,
      line    => 'if [ -f ~/.bash_git ] ; then source ~/.bash_git; fi',
      path    => "/home/${::ssh_username}/.bash_profile",
      require => [
        Exec['dotfiles'],
        Exec['bash_git'],
        ]
    }

    file_line { 'link ~/.bash_git for root':
      ensure  => present,
      line    => 'if [ -f ~/.bash_git ] ; then source ~/.bash_git; fi',
      path    => '/root/.bashrc',
      require => [
        Exec['dotfiles'],
        Exec['bash_git'],
        ]
    }

    file_line { 'link ~/.bash_aliases':
      ensure  => present,
      line    => 'if [ -f ~/.bash_aliases ] ; then source ~/.bash_aliases; fi',
      path    => "/home/${::ssh_username}/.bash_profile",
      require => File_line['link ~/.bash_git']
    }

    file_line { 'link ~/.bash_aliases for root':
      ensure  => present,
      line    => 'if [ -f ~/.bash_aliases ] ; then source ~/.bash_aliases; fi',
      path    => '/root/.bashrc',
      require => File_line['link ~/.bash_git for root']
    }

    ensure_packages(['augeas'])
  }
}

if $php_values == undef {
  $php_values = hiera('php', false)
}

case $::operatingsystem {
  'debian'           : {
    include apt::backports

    add_dotdeb { 'packages.dotdeb.org': release => $lsbdistcodename }

    if is_hash($php_values) {
      # Debian Squeeze 6.0 can do PHP 5.3 (default) and 5.4
      if $lsbdistcodename == 'squeeze' and $php_values['version'] == '54' {
        add_dotdeb { 'packages.dotdeb.org-php54': release => 'squeeze-php54' }
      }
      # Debian Wheezy 7.0 can do PHP 5.4 (default) and 5.5
       elsif $lsbdistcodename == 'wheezy' and $php_values['version'] == '55' {
        add_dotdeb { 'packages.dotdeb.org-php55': release => 'wheezy-php55' }
      }
    }

    $server_lsbdistcodename = downcase($lsbdistcodename)

    apt::force { 'git':
      release => "${server_lsbdistcodename}-backports",
      timeout => 60
    }
  }
  'ubuntu'           : {
    apt::key { '4F4EA0AAE5267A6C': key_server => 'hkp://keyserver.ubuntu.com:80' }

    apt::key { '4CBEDD5A': key_server => 'hkp://keyserver.ubuntu.com:80' }

    apt::ppa { 'ppa:pdoes/ppa': require => Apt::Key['4CBEDD5A'] }

    if is_hash($php_values) {
      # Ubuntu Lucid 10.04, Precise 12.04, Quantal 12.10 and Raring 13.04 can do PHP 5.3 (default <= 12.10) and 5.4 (default <=
      # 13.04)
      if $lsbdistcodename in [
        'lucid',
        'precise',
        'quantal',
        'raring'] and $php_values['version'] == '54' {
        if $lsbdistcodename == 'lucid' {
          apt::ppa { 'ppa:ondrej/php5-oldstable':
            require => Apt::Key['4F4EA0AAE5267A6C'],
            options => ''
          }
        } else {
          apt::ppa { 'ppa:ondrej/php5-oldstable': require => Apt::Key['4F4EA0AAE5267A6C'] }
        }
      }
      # Ubuntu Precise 12.04, Quantal 12.10 and Raring 13.04 can do PHP 5.5
       elsif $lsbdistcodename in [
        'precise',
        'quantal',
        'raring'] and $php_values['version'] == '55' {
        apt::ppa { 'ppa:ondrej/php5': require => Apt::Key['4F4EA0AAE5267A6C'] }
      } elsif $lsbdistcodename in ['lucid'] and $php_values['version'] == '55' {
        err('You have chosen to install PHP 5.5 on Ubuntu 10.04 Lucid. This will probably not work!')
      }
    }
  }
  'redhat', 'centos' : {
    if is_hash($php_values) {
      if $php_values['version'] == '54' {
        class { 'yum::repo::remi': }
      }
      # remi_php55 requires the remi repo as well
       elsif $php_values['version'] == '55' {
        class { 'yum::repo::remi': }

        class { 'yum::repo::remi_php55': }
      }
    }
  }
}

if !empty($server_values['packages']) {
  ensure_packages($server_values['packages'])
}

define add_dotdeb (
  $release) {
  apt::source { $name:
    location          => 'http://packages.dotdeb.org',
    release           => $release,
    repos             => 'all',
    required_packages => 'debian-keyring debian-archive-keyring',
    key               => '89DF5277',
    key_server        => 'keys.gnupg.net',
    include_src       => true
  }
}

# Begin MailCatcher manifest

if $mailcatcher_values == undef {
  $mailcatcher_values = hiera('mailcatcher', false)
}

if $mailcatcher_values['install'] != undef and $mailcatcher_values['install'] == 1 {
  $mailcatcher_path      = $mailcatcher_values['settings']['path']
  $mailcatcher_smtp_ip   = $mailcatcher_values['settings']['smtp_ip']
  $mailcatcher_smtp_port = $mailcatcher_values['settings']['smtp_port']
  $mailcatcher_http_ip   = $mailcatcher_values['settings']['http_ip']
  $mailcatcher_http_port = $mailcatcher_values['settings']['http_port']
  $mailcatcher_log       = $mailcatcher_values['settings']['log']

  class { 'mailcatcher':
    mailcatcher_path => $mailcatcher_path,
    smtp_ip          => $mailcatcher_smtp_ip,
    smtp_port        => $mailcatcher_smtp_port,
    http_ip          => $mailcatcher_http_ip,
    http_port        => $mailcatcher_http_port,
  }

  if !defined(Class['supervisord']) {
    class { 'supervisord': install_pip => true, }
  }

  $supervisord_mailcatcher_options = sort(join_keys_to_values({
    ' --smtp-ip'   => $mailcatcher_smtp_ip,
    ' --smtp-port' => $mailcatcher_smtp_port,
    ' --http-ip'   => $mailcatcher_http_ip,
    ' --http-port' => $mailcatcher_http_port
  }
  , ' '))

  $supervisord_mailcatcher_cmd     = "mailcatcher ${supervisord_mailcatcher_options} -f  >> ${mailcatcher_log}"

  supervisord::program { 'mailcatcher':
    command     => $supervisord_mailcatcher_cmd,
    priority    => '100',
    user        => 'mailcatcher',
    autostart   => true,
    autorestart => true,
    environment => {
      'PATH' => "/bin:/sbin:/usr/bin:/usr/sbin:${mailcatcher_path}:"
    }
    ,
    require     => Package['mailcatcher']
  }
}

# # Begin Nginx manifest

if $nginx_values == undef {
  $nginx_values = hiera('nginx', false)
}

if $php_values == undef {
  $php_values = hiera('php', false)
}

if $::osfamily == 'debian' and $lsbdistcodename in ['lucid'] and is_hash($php_values) and $php_values['version'] == '53' {
  apt::key { '67E15F46': key_server => 'hkp://keyserver.ubuntu.com:80' }

  apt::ppa { 'ppa:l-mierzwa/lucid-php5':
    options => '',
    require => Apt::Key['67E15F46']
  }
}

include puphpet::params

$php5_fpm_sock = '/var/run/php5-fpm.sock'

if $php_values['version'] == undef {
  $fastcgi_pass = null
} elsif $php_values['version'] == '53' {
  $fastcgi_pass = '127.0.0.1:9000'
} else {
  $fastcgi_pass = "unix:${php5_fpm_sock}"
}

# Nginx manifest
class { 'nginx':
  manage_repo        => $nginx_values['manage_repo'],
  confd_purge        => $nginx_values['confd_purge'],
  configtest_enable  => $nginx_values['configtest_enable'],
  worker_processes   => $nginx_values['worker_processes'],
  worker_connections => $nginx_values['worker_connections'],
  gzip               => $nginx_values['gzip'],
  http_cfg_append    => $nginx_values['http_cfg_append']
}

# Make php listen to the socket
file_line { 'php-fpm-listen':
  line    => "listen = ${nginx_values['fpm_socket']}",
  path    => '/etc/php-fpm.d/www.conf',
  match   => '^listen = (.*)$',
  ensure  => present,
  require => [Class['php']],
  notify  => Service['php-fpm']
}

file_line { 'php-fpm-user':
  line    => 'user = www-data',
  path    => '/etc/php-fpm.d/www.conf',
  match   => '^user = (.*)$',
  ensure  => present,
  require => [Class['php']],
  notify  => Service['php-fpm']
}

file_line { 'php-fpm-group':
  line    => 'group = www-data',
  path    => '/etc/php-fpm.d/www.conf',
  match   => '^group = (.*)$',
  ensure  => present,
  require => [Class['php']],
  notify  => Service['php-fpm']
}

# Create the nginx vhosts, if defined
if has_key($nginx_values, 'vhosts') and count($nginx_values['vhosts']) > 0 {
  create_resources(nginx::resource::vhost, $nginx_values['vhosts'])
}

# Create the nginx locations, if defined
if has_key($nginx_values, 'locations') and count($nginx_values['locations']) > 0 {
  create_resources(nginx::resource::location, $nginx_values['locations'])
}

# End nginx manifest


# # Begin PHP manifest
if $php_values == undef {
  $php_values = hiera('php', false)
}

if $apache_values == undef {
  $apache_values = hiera('apache', false)
}

if $nginx_values == undef {
  $nginx_values = hiera('nginx', false)
}

Class['Php'] -> Class['Php::Devel'] -> Php::Module <| |> -> Php::Pear::Module <| |> -> Php::Pecl::Module <| |>

if $php_prefix == undef {
  $php_prefix = $::operatingsystem ? {
    /(?i: Ubuntu|Debian|Mint|SLES|OpenSuSE)/ => 'php5-',
    default => 'php-',
  } }

if $php_fpm_ini == undef {
  $php_fpm_ini = $::operatingsystem ? {
    /(?i: Ubuntu|Debian|Mint|SLES|OpenSuSE)/ => '/etc/php5/fpm/php.ini',
    default => '/etc/php.ini',
  } }

if is_hash($apache_values) {
  include apache::params

  if has_key($apache_values, 'mod_spdy') and $apache_values['mod_spdy'] == 1 {
    $php_webserver_service_ini = 'cgi'
  } else {
    $php_webserver_service_ini = 'httpd'

    if $webserver_service == undef {
      $webserver_service = 'httpd'
    }
  }

  $php_webserver_service = 'httpd'
  $php_webserver_user    = $apache::params::user
  $php_webserver_restart = true

  class { 'php':
    package             => $php_webserver_service,
    service             => $php_webserver_service,
    service_autorestart => true,
  }
} elsif is_hash($nginx_values) {
  if $webserver_service == undef {
    $webserver_service = 'nginx'
  }

  include nginx::params

  $php_webserver_service     = "${php_prefix}fpm"
  $php_webserver_service_ini = $php_webserver_service
  $php_webserver_user        = $nginx::params::nx_daemon_user
  $php_webserver_restart     = true

  class { 'php':
    package             => $php_webserver_service,
    service             => $php_webserver_service,
    service_autorestart => false,
    config_file         => $php_fpm_ini,
  }

  service { $php_webserver_service:
    ensure     => running,
    enable     => true,
    hasrestart => true,
    hasstatus  => true,
    require    => Package[$php_webserver_service]
  }
} else {
  $php_webserver_service     = undef
  $php_webserver_service_ini = undef
  $php_webserver_restart     = false

  class { 'php':
    package             => "${php_prefix}cli",
    service             => $php_webserver_service,
    service_autorestart => true,
  }
}

class { 'php::devel':
}

if count($php_values['modules']['php']) > 0 {
  php_mod { $php_values['modules']['php']: ; }
}

if count($php_values['modules']['pear']) > 0 {
  php_pear_mod { $php_values['modules']['pear']: ; }
}

if count($php_values['modules']['pecl']) > 0 {
  php_pecl_mod { $php_values['modules']['pecl']: ; }
}

if count($php_values['ini']) > 0 {
  each($php_values['ini']) |$key, $value| {
    if is_array($value) {
      each($php_values['ini'][$key]) |$innerkey, $innervalue| {
        puphpet::ini { "${key}_${innerkey}":
          entry       => "CUSTOM_${innerkey}/${key}",
          value       => $innervalue,
          php_version => $php_values['version'],
          webserver   => $php_webserver_service_ini
        }
      }
    } else {
      puphpet::ini { $key:
        entry       => "CUSTOM/${key}",
        value       => $value,
        php_version => $php_values['version'],
        webserver   => $php_webserver_service_ini
      }
    }
  }

  if $php_values['ini']['session.save_path'] != undef {
	file {"${php_values['ini']['session.save_path']}":
		ensure => directory,
		owner  => 'www-data',
		require => [Class['php']],
		recurse => true,
		mode   => 0775
	}
  }
}

puphpet::ini { 'php-timezone':
  entry       => 'CUSTOM/date.timezone',
  value       => $php_values['timezone'],
  php_version => $php_values['version'],
  webserver   => $php_webserver_service_ini
}
puphpet::ini { 'php-tokens':
	entry       => 'CUSTOM/expose_php',
	value       => $php_values['expose_php'],
	php_version => $php_values['version'],
	webserver   => $php_webserver_service_ini
}

define php_mod {
  php::module { $name: service_autorestart => $php_webserver_restart, }
}

define php_pear_mod {
  php::pear::module { $name:
    use_package         => false,
    service_autorestart => $php_webserver_restart,
  }
}

define php_pecl_mod {
  puphpet::ini { "extension_${name}":
    entry       => "CUSTOM_${name}/extension",
    value       => "${name}.so",
    php_version => $php_values['version'],
    webserver   => $php_webserver_service_ini
  }

  php::pecl::module { $name:
    use_package         => "no",
    service_autorestart => $php_webserver_restart,
    preferred_state     => 'alpha',
    verbose             => true,
    require             => [Puphpet::Ini["extension_${name}"]]
  }
}

if $php_values['composer'] == 1 {
  class { 'composer':
    target_dir      => '/usr/local/bin',
    composer_file   => 'composer',
    download_method => 'curl',
    logoutput       => false,
    tmp_path        => '/tmp',
    php_package     => "${php::params::module_prefix}cli",
    curl_package    => 'curl',
    suhosin_enabled => false,
  }
}

# # Begin Xdebug manifest

if $xdebug_values == undef {
  $xdebug_values = hiera('xdebug', false)
}

if is_hash($apache_values) {
  $xdebug_webserver_service = 'httpd'
} elsif is_hash($nginx_values) {
  $xdebug_webserver_service = 'nginx'
} else {
  $xdebug_webserver_service = undef
}

if $xdebug_values['install'] != undef and $xdebug_values['install'] == 1 {
  class { 'puphpet::xdebug': webserver => $xdebug_webserver_service }

  if is_hash($xdebug_values['settings']) and count($xdebug_values['settings']) > 0 {
    each($xdebug_values['settings']) |$key, $value| {
      puphpet::ini { $key:
        entry       => "XDEBUG/${key}",
        value       => $value,
        php_version => $php_values['version'],
        webserver   => $xdebug_webserver_service
      }
    }
  }
}

# # Begin Xhprof manifest

if $xhprof_values == undef {
  $xhprof_values = hiera('xhprof', false)
}

if $apache_values == undef {
  $apache_values = hiera('apache', false)
}

if $nginx_values == undef {
  $nginx_values = hiera('nginx', false)
}

if is_hash($apache_values) or is_hash($nginx_values) {
  $xhprof_webserver_restart = true
} else {
  $xhprof_webserver_restart = false
}

if is_hash($xhprof_values) and $xhprof_values['install'] == 1 {
  if $::operatingsystem == 'ubuntu' {
    apt::key { '8D0DC64F': key_server => 'hkp://keyserver.ubuntu.com:80' }

    apt::ppa { 'ppa:brianmercer/php5-xhprof': require => Apt::Key['8D0DC64F'] }
  }

  $xhprof_package = $puphpet::params::xhprof_package

  if is_hash($apache_values) {
    $xhprof_webroot_location  = $puphpet::params::apache_webroot_location
    $xhprof_webserver_service = Service['httpd']
  } elsif is_hash($nginx_values) {
    $xhprof_webroot_location  = $puphpet::params::nginx_webroot_location
    $xhprof_webserver_service = Service['nginx']
  } else {
    $xhprof_webroot_location  = $xhprof_values['location']
    $xhprof_webserver_service = undef
  }

  if defined(Package[$xhprof_package]) == false {
    package { $xhprof_package:
      ensure  => installed,
      require => Package['php'],
      notify  => $xhprof_webserver_service,
    }
  }

  ensure_packages(['graphviz'])

  exec { 'delete-xhprof-path-if-not-git-repo':
    command => "rm -rf ${xhprofPath}",
    onlyif  => "test ! -d ${xhprofPath}/.git"
  }

  vcsrepo { "${xhprof_webroot_location}/xhprof":
    ensure   => present,
    provider => git,
    source   => 'https://github.com/facebook/xhprof.git',
    require  => Exec['delete-xhprof-path-if-not-git-repo']
  }

  file { "${xhprofPath}/xhprof_html":
    ensure  => directory,
    mode    => 0775,
    require => Vcsrepo["${xhprof_webroot_location}/xhprof"]
  }

  composer::exec { 'xhprof-composer-run':
    cmd     => 'install',
    cwd     => "${xhprof_webroot_location}/xhprof",
    require => [
      Class['composer'],
      File["${xhprofPath}/xhprof_html"]]
  }
}

# # Begin Drush manifest

if $drush_values == undef {
  $drush_values = hiera('drush', false)
}

if $drush_values['install'] != undef and $drush_values['install'] == 1 {
  if ($drush_values['settings']['drush.tag_branch'] != undef) {
    $drush_tag_branch = $drush_values['settings']['drush.tag_branch']
  } else {
    $drush_tag_branch = ''
  }

  # # @see https://drupal.org/node/2165015
  include drush::git::drush

  # # class { 'drush::git::drush':
  # #   git_branch => $drush_tag_branch,
  # #   update     => true,
  # # }
}

# # End Drush manifest

# # Begin MariaDb manifest

if $mysql_values == undef {
  $mysql_values = hiera('mysql', false)
}

if $php_values == undef {
  $php_values = hiera('php', false)
}

if $apache_values == undef {
  $apache_values = hiera('apache', false)
}

if $nginx_values == undef {
  $nginx_values = hiera('nginx', false)
}

if is_hash($apache_values) or is_hash($nginx_values) {
  $mysql_webserver_restart = true
} else {
  $mysql_webserver_restart = false
}

if has_key($mysql_values, 'root_password') and $mysql_values['root_password'] and $mysql_values['install'] == 1 {
  class { '::mysql::server':
    service_name            => $mysql_values['service_name'],
    service_enabled         => $mysql_values['service_enabled'],
    service_manage          => $mysql_values['service_manage'],
    remove_default_accounts => $mysql_values['remove_default_accounts'],
    manage_config_file      => $mysql_values['manage_config_file'],
    override_options        => $mysql_values['override_options'],
    package_name            => $mysql_values['server_package_name'],
    root_password           => $mysql_values['root_password'],
  }

  class { '::mysql::client':
    package_name => $mysql_values['client_package_name'],
  }

  if is_hash($mysql_values['databases']) and count($mysql_values['databases']) > 0 {
    create_resources(mysql_db, $mysql_values['databases'])
  }

  if is_hash($php_values) {
    if $::osfamily == 'redhat' and $php_values['version'] == '53' and !defined(Php::Module['mysql']) {
      php::module { 'mysql': service_autorestart => $mysql_webserver_restart, }
    } elsif !defined(Php::Module['mysqlnd']) {
      php::module { 'mysqlnd': service_autorestart => $mysql_webserver_restart, }
    }
  }
}

define mysql_db (
  $user,
  $password,
  $host,
  $grant    = [],
  $sql_file = false) {
  if $name == '' or $password == '' or $host == '' {
    fail('MariaDB requires that name, password and host be set. Please check your settings!')
  }

  mysql::db { $name:
    user     => $user,
    password => $password,
    host     => $host,
    grant    => $grant,
    sql      => $sql_file,
    require  => [Class['::mysql::server']]
  }
}

file { '/usr/share/nginx':
  owner   => $::ssh_username,
  ensure  => directory,
  require => [Class['nginx']],
  recurse => true,
  mode    => 0755
}
file { '/usr/share/nginx/html':
	owner   => $::ssh_username,
	ensure  => directory,
	require => [File['/usr/share/nginx']],
	recurse => true,
	mode    => 0755
}

if has_key($mysql_values, 'phpmyadmin') and $mysql_values['phpmyadmin'] == 1 and is_hash($php_values) and defined(Class['mysql::server'
  ]) == true {
  if $::osfamily == 'debian' {
    if $::operatingsystem == 'ubuntu' {
      apt::key { '80E7349A06ED541C': key_server => 'hkp://keyserver.ubuntu.com:80' }

      apt::ppa { 'ppa:nijel/phpmyadmin': require => Apt::Key['80E7349A06ED541C'] }
    }

    $phpMyAdmin_package = 'phpmyadmin'
    $phpMyAdmin_folder  = 'phpmyadmin'
  } elsif $::osfamily == 'redhat' {
    $phpMyAdmin_package = 'phpMyAdmin.noarch'
    $phpMyAdmin_folder  = 'phpMyAdmin'
  }

  if !defined(Package[$phpMyAdmin_package]) {
    package { $phpMyAdmin_package:
	    require => [
        Class['mysql::server'],
        Service[$webserver_service]]
    }
  }

  include puphpet::params

  if is_hash($apache_values) {
    $mysql_pma_webroot_location = $puphpet::params::apache_webroot_location
  } elsif is_hash($nginx_values) {
    $mysql_pma_webroot_location = $puphpet::params::nginx_webroot_location
  }

  exec { 'cp phpmyadmin to webroot':
    command => "cp -LR /usr/share/${phpMyAdmin_folder} ${mysql_pma_webroot_location}/phpmyadmin",
    onlyif  => "test ! -d ${mysql_pma_webroot_location}/phpmyadmin",
    require => [
      File['/usr/share/nginx'],
      Package[$phpMyAdmin_package],
      File[$mysql_pma_webroot_location]
	]
  }
}

if has_key($mysql_values, 'adminer') and $mysql_values['adminer'] == 1 and is_hash($php_values) {
  if is_hash($apache_values) {
    $mysql_adminer_webroot_location = $puphpet::params::apache_webroot_location
  } elsif is_hash($nginx_values) {
    $mysql_adminer_webroot_location = $puphpet::params::nginx_webroot_location
  } else {
    $mysql_adminer_webroot_location = $puphpet::params::apache_webroot_location
  }

  class { 'puphpet::adminer':
    location => "${mysql_adminer_webroot_location}/adminer",
    owner    => 'www-data',
    require  => [
      File['/usr/share/nginx'],
      Service[$webserver_service]]
  }
}

# # Begin MongoDb manifest

if $mongodb_values == undef {
  $mongodb_values = hiera('mongodb', false)
}

if $php_values == undef {
  $php_values = hiera('php', false)
}

if $apache_values == undef {
  $apache_values = hiera('apache', false)
}

if $nginx_values == undef {
  $nginx_values = hiera('nginx', false)
}

if is_hash($apache_values) or is_hash($nginx_values) {
  $mongodb_webserver_restart = true
} else {
  $mongodb_webserver_restart = false
}

if has_key($mongodb_values, 'install') and $mongodb_values['install'] == 1 {
  case $::osfamily {
    'debian' : {
      class { '::mongodb::globals': manage_package_repo => true, } ->
      class { '::mongodb::server':
        auth => $mongodb_values['auth'],
        port => $mongodb_values['port'],
      }

      $mongodb_pecl = 'mongo'
    }
    'redhat' : {
      class { '::mongodb::globals': manage_package_repo => true, } ->
      class { '::mongodb::server':
        auth => $mongodb_values['auth'],
        port => $mongodb_values['port'],
      } ->
      class { '::mongodb::client': }

      $mongodb_pecl = 'pecl-mongo'
    }
  }

  if is_hash($mongodb_values['databases']) and count($mongodb_values['databases']) > 0 {
    create_resources(mongodb_db, $mongodb_values['databases'])
  }

  if is_hash($php_values) and !defined(Php::Pecl::Module[$mongodb_pecl]) {
    php::pecl::module { $mongodb_pecl:
      service_autorestart => $mysql_webserver_restart,
      require             => Class['::mongodb::server']
    }
  }
}

define mongodb_db (
  $user,
  $password) {
  if $name == '' or $password == '' {
    fail('MongoDB requires that name and password be set. Please check your settings!')
  }

  mongodb::db { $name:
    user     => $user,
    password => $password
  }
}

# Begin beanstalkd

if $beanstalkd_values == undef {
  $beanstalkd_values = hiera('beanstalkd', false)
}

if $php_values == undef {
  $php_values = hiera('php', false)
}

if $apache_values == undef {
  $apache_values = hiera('apache', false)
}

if $nginx_values == undef {
  $nginx_values = hiera('nginx', false)
}

if is_hash($apache_values) {
  $beanstalk_console_webroot_location = "${puphpet::params::apache_webroot_location}/beanstalk_console"
} elsif is_hash($nginx_values) {
  $beanstalk_console_webroot_location = "${puphpet::params::nginx_webroot_location}/beanstalk_console"
} else {
  $beanstalk_console_webroot_location = undef
}

if has_key($beanstalkd_values, 'install') and $beanstalkd_values['install'] == 1 {
  create_resources(beanstalkd::config, {
    'beanstalkd' => $beanstalkd_values['settings']
  }
  )

  if has_key($beanstalkd_values, 'beanstalk_console') and $beanstalkd_values['beanstalk_console'] == 1 and 
  $beanstalk_console_webroot_location != undef and is_hash($php_values) {
    exec { 'delete-beanstalk_console-path-if-not-git-repo':
      command => "rm -rf ${beanstalk_console_webroot_location}",
      onlyif  => "test ! -d ${beanstalk_console_webroot_location}/.git"
    }

    vcsrepo { $beanstalk_console_webroot_location:
      ensure   => present,
      provider => git,
      source   => 'https://github.com/ptrofimov/beanstalk_console.git',
      require  => Exec['delete-beanstalk_console-path-if-not-git-repo']
    }
  }
}

# Begin rabbitmq

if $rabbitmq_values == undef {
  $rabbitmq_values = hiera('rabbitmq', false)
}

if $php_values == undef {
  $php_values = hiera('php', false)
}

if has_key($rabbitmq_values, 'install') and $rabbitmq_values['install'] == 1 {
  class { 'rabbitmq': port => $rabbitmq_values['port'] }

  if is_hash($php_values) and !defined(Php::Pecl::Module['amqp']) {
    php_pecl_mod { 'amqp': }
  }
}

# Begin elastic search

if $elasticsearch_values == undef {
  $elasticsearch_values = hiera('elastic_search', false)
}

if has_key($elasticsearch_values, 'install') and $elasticsearch_values['install'] == 1 {
  case $::osfamily {
    'debian' : { $package_url = 'https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.7.deb' }
    'redhat' : { $package_url = 'https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.10.noarch.rpm' }
    default  : { fail('Unrecognized operating system for Elastic Search') }
  }

  class { 'elasticsearch':
    java_install => true,
    autoupgrade  => true,
    package_url  => $package_url
  }
}

# Nodejs manifest
$nodejsValues = hiera('nodejs', false)

if is_hash($nodejsValues) and $nodejsValues['install'] == 1 {
  class { 'nodejs':
    version      => $nodejsValues['version'],
    make_install => $nodejsValues['make_install'],
    target_dir   => $nodejsValues['target_dir']
  }

  $nodePckgs = hiera('nodejs_packages', false)

  if is_hash($nodePckgs) and count($nodePckgs) > 0 {
    create_resources(package, $nodePckgs)
  }
}

# VSFTPD Manifest
$vsftpd_values = hiera('vsftpd', false)

if is_hash($vsftpd_values) and $vsftpd_values['install'] == 1 {
  class { 'vsftpd':
    puppi                   => $vsftpd_values['puppi'],
    template                => $vsftpd_values['template'],
    service_status          => $vsftpd_values['service_status'],
    firewall                => $vsftpd_values['firewall'],
    local_enable            => $vsftpd_values['local_enable'],
    port                    => $vsftpd_values['port'],
    protocol                => $vsftpd_values['protocol'],
    anonymous_enable        => $vsftpd_values['anonymous_enable'],
	pam_service_name        => $vsftpd_values['pam_service_name'],
    anon_mkdir_write_enable => $vsftpd_values['anon_mkdir_write_enable'],
    anon_upload_enable      => $vsftpd_values['anon_upload_enable'],
    chroot_local_user       => $vsftpd_values['chroot_local_user'],
    connect_from_port_20    => $vsftpd_values['connect_from_port_20'],
    ftpd_banner             => $vsftpd_values['ftpd_banner'],
    guest_enable            => $vsftpd_values['guest_enable'],
    hide_ids                => $vsftpd_values['hide_ids'],
  }

  if $vsftpd_values['manage_users'] == 1 and is_hash($vsftpd_values['users']) and count($vsftpd_values['users']) > 0 {
    create_resources(user, $vsftpd_values['users'])
  }
}
# Memcached manifest
$memcached_values = hiera('memcached', false)

if is_hash($memcached_values) and $memcached_values['install'] == 1 {
  class { 'memcached':
    package_ensure  => $memcached_values['package_ensure'],
    logfile         => $memcached_values['logfile'],
    manage_firewall => $memcached_values['manage_firewall'],
    max_memory      => $memcached_values['max_memory'],
    item_size       => $memcached_values['item_size'],
    lock_memory     => $memcached_values['lock_memory'],
    listen_ip       => $memcached_values['listen_ip'],
    tcp_port        => $memcached_values['tcp_port'],
    udp_port        => $memcached_values['udp_port'],
    max_connections => $memcached_values['max_connections'],
    install_dev     => $memcached_values['install_dev'],
    processorcount  => $memcached_values['processorcount'],
  }
}

# Mosquitto manifest - http://www.mosquitto.org/
$mosquitto_values = hiera('mosquitto', false)

if $mosquitto_values['install'] == 1 {
  class { 'mosquitto':
    listen_ip   => $mosquitto_values['listen_ip'],
    listen_port => $mosquitto_values['listen_port'],
  }
}

# PhalconPHP Manifest
$phalconphp_values = hiera('phalcon', false)

if $phalconphp_values['install'] == 1 {
	class {'phalconphp':
		ensure_sys_deps=>$phalconphp_values['ensure_sys_deps'],
		ensure=>$phalconphp_values['ensure'],
		install_devtools=>$phalconphp_values['install_devtools'],
		devtools_version=>$phalconphp_values['devtools_version'],
		install_zephir=>$phalconphp_values['install_zephir'],
		compat_sys_deps=>$phalconphp_values['compat_sys_deps'],
		zephir_build=>$phalconphp_values['zephir_build'],
		ini_file=>$phalconphp_values['ini_file'],
		debug=>$phalconphp_values['debug']
	}
}

# Redis Manifest
$redis_values = hiera('redis', true)

if $redis_values['install'] == 1 {
  class { 'redis':
    bind           => $redis_values['bind'],
    port           => $redis_values['port'],
    service_group  => $redis_values['service_group'],
    service_user   => $redis_values['service_user'],
    manage_repo    => $redis_values['manage_repo'],
    service_enable => $redis_values['service_enable'],
    config_owner   => $redis_values['config_owner']
  }
}

# Host entries manifest
$host_entries = hiera('host_entries', false)

if $host_entries['manage'] == 1 and count($host_entries['entries']) > 0 {
  create_resources(host, $host_entries['entries'])
}

# Authorized SSH Keys
$authorized_ssh_keys = hiera('ssh_auth_keys', false)

if $authorized_ssh_keys['manage'] == 1 and count($authorized_ssh_keys['keys']) > 0 {
  create_resources(ssh_authorized_key, $authorized_ssh_keys['keys'])
}

# Sudo config manifest:
if $sudo_config == undef {
  $sudo_config = hiera('sudo_config', false)
}

if $sudo_config['manage'] == 1 {

}

# SSH Config manifest
$ssh_config = hiera('ssh_config', false)

if $ssh_config['manage'] == 1 {


  firewall {'010 allow ssh':
  	ensure      => present,
  	port        => [$ssh_config['port']],
  	proto       => 'tcp',
  	action      => 'accept',
  	destination => $::ipaddress_eth0
  }

  class { 'openssh':
    port                    => $ssh_config['port'],
    replace_config          => $ssh_config['replace_config'],
    permit_root_login       => $ssh_config['permit_root_login'],
    log_level               => $ssh_config['log_leveel'],
    x11_forwarding          => $ssh_config['x11_forwarding'],
    max_auth_tries          => $ssh_config['max_auth_tries'],
    password_authentication => $ssh_config['password_authentication'],
    client_alive_interval   => $ssh_config['client_alive_interval'],
    client_alive_count_max  => $ssh_config['client_alive_count_max'],
    allow_users             => $ssh_config['allow_users'],
    deny_users              => $ssh_config['deny_users'],
    banner                  => $ssh_config['banner'],
    sftp_chroot             => $ssh_config['sftp_chroot'],
    config_template         => $ssh_config['config_template'],
    service_name            => $ssh_config['service_name'],
    package_name            => $ssh_config['package_name'],
    service_enable          => $ssh_config['service_enable'],
    package_ensure          => $ssh_config['package_ensure'],
    restart_service         => $ssh_config['restart_service'],
	require                 => $ssh_config['require'],
	notify                  => Service[$ssh_config['service_name']]
  }
}
