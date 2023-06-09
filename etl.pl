#!/usr/bin/env perl

use LWP::UserAgent;
use Getopt::Long;
use JSON::PP;
use Carp;
use HTTP::Request;
use URI;
use v5.32;

my $ua = LWP::UserAgent->new();
my $tsc_url = $ENV{TSC_URL};
my $tsc_key = $ENV{TSC_KEY};
my $tsc_secret = $ENV{TSC_SECRET};

sub log_and_croak {
  my ($code, $res) = @_;
  my $msg = encode_json($res);
  croak "$code: $msg";
}

sub http_request {
  my ($method, $route, $d) = @_;
  my $url = URI->new("$tsc_url/rest/$route");
  if ($d->{query}) {
    $url->query_form(%{$d->{query}});
  }
  my $req = HTTP::Request->new($method, $url);
  $req->header('Content-Type' => 'application/json');
  $req->header('x-apikey' => "accesskey=$tsc_key; secretkey=$tsc_secret;");
  if (defined $d->{data}) {
    my $jsn = encode_json($d->{data});
    $req->content($jsn);
  }
  my $res = $ua->request($req);
  my $t = $res->content;
  my $h = decode_json($t);
  return ($res->code, $h);
}

sub get_scans {
  my ($code, $d) = http_request('GET', '/scan');
  say encode_json($d);
}

sub get_scan_results {
  my ($code, $d) = http_request('GET', "/scanResult");
  say encode_json($d);
} 

sub get_scan_result {
  my $id = shift;
  my ($code, $d) = http_request('GET', "/scanResult/$id");
  say encode_json($d);
}

sub get_device_info {
  my $ip = shift;
  my ($code, $d) = http_request('GET', "/deviceInfo", {query => {ip => $ip}});
  say encode_json($d);
}

sub get_analysis {
  my %params = @_;
  my $h = {
    query => {
      tool => 'vulnipsummary',
      endOffset => 1000,
      startOffset => 0,
      type => 'vuln',
      filters => []
    },
    type => 'vuln',
    sourceType => $params{source_type} || 'cumulative'  # cumulative or patched
  };
  my ($code, $d) = http_request('POST', "/analysis", {data => $h});
  say encode_json($d);
}

sub main {
  my $arg = shift @ARGV;
  GetOptions(
    'id=i' => \my $id,
    'ip=s' => \my $ip,
    'scan-id=s' => \my $scan_id,
    'source-type=s' => \my $source_type
  );
  if ($arg =~ /^scans$/) {
    get_scans;
  } elsif ($arg =~ /^results$/) {
    get_scan_results;
  } elsif ($arg =~ /^result$/) {
    get_scan_result($id);
  } elsif ($arg =~ /^device-info$/) {
    get_device_info($ip);
  } elsif ($arg =~ /^analysis$/) {
    get_analysis(source_type => $source_type);
  } else {
    say "bad arg: $arg";
  }
}

main;
