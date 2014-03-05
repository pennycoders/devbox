#!/usr/bin/perl
 
use strict;
use Puppet::Tidy;
 
my (@output, $source);
 
$source = << 'EOP';
  file { 'space': mode => $mode }
EOP
 
Puppet::Tidy::puppettidy(source => $source, destination => \@output);