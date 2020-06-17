<?php
declare(strict_types = 1);

$certTypes = ['root', 'intermediate'];

foreach ($certTypes as $type)
{
	${$type . "Certificates"} = array();
	$certs = file_get_contents("./$type-certificates.pem");
	while (strpos($certs, '-----BEGIN CERTIFICATE-----') !== false) {
		$start = strpos($certs, '-----BEGIN CERTIFICATE-----');
		$end = strpos($certs, '-----END CERTIFICATE-----') + 25;
		$pem = substr($certs, $start, $end - $start);
		${$type . "Certificates"}[] = ['pem' => $pem, 'parsed' => openssl_x509_parse($pem, false)];
		$certs = substr($certs, $end);
	}
}

$leaf = file_get_contents($argv[1]);
$crt = openssl_x509_parse($leaf, false);
$store[getHash($leaf)] = $crt;

if (isset($crt['extensions']['authorityKeyIdentifier'])) {
	$chain = [getHash($leaf) => checkParents($crt, $certTypes, $rootCertificates, $intermediateCertificates, $store)];
	prettyPrintChain($chain, $store);
}

function getHash($pem)
{
	$der = base64_decode(trim(str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $pem)));
	return bin2hex(hash('sha256', $der, true));
}

function checkParents($candidate, $certTypes, $rootCertificates, $intermediateCertificates, &$store)
{
	$parents = [];
	foreach ($certTypes as $type) {
		foreach (${$type . "Certificates"} as $certificate) {
			if (isset($certificate['parsed']['extensions']['subjectKeyIdentifier']) &&
				isset($candidate['extensions']['authorityKeyIdentifier']) &&
				$certificate['parsed']['extensions']['subjectKeyIdentifier'] === trim(str_replace('keyid:', '', $candidate['extensions']['authorityKeyIdentifier']))) {
				$hash = getHash($certificate['pem']);
				$parents[$hash] = [];
				$store[$hash] = $certificate['parsed'];
			}
		}
	}
	if (count($parents) > 0) {
		foreach ($parents as $hash => $arr) {
			$parents[$hash] = checkParents($store[$hash], $certTypes, $rootCertificates, $intermediateCertificates, $store);
		}
	}
	return $parents;
}

function prettyPrintChain($chain, $store, $chainNumber = 0, $chainSoFar = []) {
	foreach ($chain as $key => $value) {
		if (count($value) > 0) {
			$history = $chainSoFar;
			$history[] = $key;
			prettyPrintChain($value, $store, $chainNumber, $history);
		} else {
			foreach ($chainSoFar as $parent) {
				echo $chainNumber . ": " . $parent . "\r\n";
				echo $store[$parent]['subject']['commonName'] . "\r\n";
			}
			echo $chainNumber . ": " . $key . "\r\n";
			echo $store[$key]['subject']['commonName'] . "\r\n";
		}
		$chainNumber++;
	}
}

