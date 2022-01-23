<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\MassDestroySigningCertificateRequest;
use App\Http\Requests\StoreSigningCertificateRequest;
use App\Http\Requests\UpdateSigningCertificateRequest;
use App\Cert;
use App\Params;
use File;
use Carbon\Carbon;
use ZipArchive;

class SigningRequestController extends Controller
{
    public function create()
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

        $params = Params::all();

        return view('admin.certs.sign-req.create', compact('params'));
    }

    public function store(StoreSigningCertificateRequest $request)
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

        $subjectCommonName = openssl_csr_get_subject($request->certificateServerRequest, true);
        $cacert = file_get_contents('/opt/ca/cacert.pem');
        $pkeyid = array(file_get_contents('/opt/ca/private/cakey.pem'), $request->password );
        $serial = random_int(260001, 270001); // serial for external CSR

        // Default location for OpenSSL Config file.
        $config = '/usr/lib/ssl/openssl.cnf';

        // Clear SAN DNS entries if previous error.
        shell_exec("sudo /opt/subjectAltNameRemoval.sh 2>&1");

        // Extracting SAN fron CSR.
		$random_blurp = rand(1000,99999);
		$tempCSR = "/tmp/csr-" . $random_blurp . ".csr.pem";
		$write_csr = file_put_contents($tempCSR, $request->certificateServerRequest);
		if($write_csr !== FALSE) {
			$san = trim(shell_exec("openssl req -noout -text -in " . $tempCSR . " | grep -e 'DNS:' -e 'IP:' -e 'email:'")); // Not sure if 'email:' works.
		}
		unlink($tempCSR);

		// In case the CSR file doesn´t include SAN.
		if($san == ""){
            $san = 'DNS:' . $subjectCommonName['CN'];
            }

        // Include subjectAltName in openssl.cnf.
        $caConfFile = file_get_contents($config);

        // Do replacements for SAN in ca.cnf.
        $caConfFile = str_replace("DNS:",$san, $caConfFile);
        file_put_contents($config, $caConfFile);
        unset($caConfFile); // Clears the content of the file.

        $configArgs = array(
            'config' => $config,
            'encrypt_key' => false,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'digest_alg' => $request->signatureTypeSN,
            'x509_extensions' => $request->extensionsExtendedKeyUsage );

        // Sign certificate and export to string.
        $cert = openssl_csr_sign($request->certificateServerRequest , $cacert, $pkeyid, $request->validityPeriod, $configArgs, $serial);
        openssl_x509_export($cert, $publicKey);

        // Save and zip CSR and Cert in file to ZIP//
        file_put_contents(storage_path('archives/tmp/cert.csr'), $request->certificateServerRequest);
        file_put_contents(storage_path('archives/tmp/cert.cer'), $publicKey);

        // Clean SAN DNS entries.
        shell_exec("sudo /opt/subjectAltNameRemoval.sh 2>&1");

        // Parse Certificate Info.
        $cert_parse = openssl_x509_parse($publicKey);

        $request['publicKey'] = $publicKey;
        $request['name'] = $cert_parse['name'];
        $request['subject'] = $cert_parse['subject'];
        $request['subjectCommonName'] = $cert_parse['subject']['CN'];
        $request['subjectContry'] = $cert_parse['subject']['C'];
        $request['subjectState'] = $cert_parse['subject']['ST'];
        $request['subjectLocality'] = $cert_parse['subject']['L'];
        $request['subjectOrganization'] = $cert_parse['subject']['O'];
        $request['subjectOrganizationUnit'] = $cert_parse['subject']['OU'];
        $request['hash'] = $cert_parse['hash'];
        $request['issuer'] = $cert_parse['issuer'];
        $request['issuerCN'] = $cert_parse['issuer']['CN'];
        $request['issuerContry'] = $cert_parse['issuer']['C'];
        $request['issuerState'] = $cert_parse['issuer']['ST'];
            //$request['issuerLocality'] = $cert_parse['issuer']['L'];
            $request['issuerOrganization'] = $cert_parse['issuer']['O'];
            $request['issuerOrganizationUnit'] = $cert_parse['issuer']['OU'];
            $request['version'] = $cert_parse['version'];
            $request['serialNumber'] = $cert_parse['serialNumber'];
            $request['serialNumberHex'] = $cert_parse['serialNumberHex'];
            $request['validFrom'] = $cert_parse['validFrom'];
            $request['validTo'] = $cert_parse['validTo'];
            $request['validFrom_time_t'] = $cert_parse['validFrom_time_t'];
            $request['validTo_time_t'] = $cert_parse['validTo_time_t'];
            $request['signatureTypeSN'] = $cert_parse['signatureTypeSN'];
            $request['signatureTypeLN'] = $cert_parse['signatureTypeLN'];
            $request['signatureTypeNID'] = $cert_parse['signatureTypeNID'];
        //$purposes = $cert_parse['purposes']['1']['2']; dd($purposes);
        $request['purposes'] = 'Not Implemented';
        $request['extensions'] = $cert_parse['extensions'];
        $request['extensionsBasicConstraints'] = $cert_parse['extensions']['basicConstraints'];
            //$extensionsExtendedKeyUsage = $cert_parse['extensions']['nsCertType'];
            $request['extensionsKeyUsage'] = $cert_parse['extensions']['keyUsage'];
            $request['extensionsExtendedKeyUsage'] = $cert_parse['extensions']['extendedKeyUsage'];
            $request['extensionsSubjectKeyIdentifier'] = $cert_parse['extensions']['subjectKeyIdentifier'];
            $request['extensionsAuthorityKeyIdentifier'] = $cert_parse['extensions']['authorityKeyIdentifier'];
            $request['extensionsSubjectAltName'] = $cert_parse['extensions']['subjectAltName'];
            $request['extensionsCrlDistributionPoints'] = $cert_parse['extensions']['crlDistributionPoints'];

        /** Convert dates. */
        $validTo_time_t = date(DATE_RFC2822, $request['validTo_time_t']);
        $expiryDate = Carbon::parse(Carbon::now())->diffInDays($validTo_time_t);
        $request['expiryDate'] = $expiryDate;
        $cert = Cert::create($request->all(), $publicKey);
        $cert->save();

        /** Zip the .cer and .key saved in storage_path/tmp and move it to storage_path/archives. */
        $zipFile = $cert->id . '.zip';
        $zip = new ZipArchive();
        $path = storage_path('archives/keypairs/');

        $zip->open($path . $zipFile, ZipArchive::CREATE | ZipArchive::CREATE);

        //$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));
        $files = File::files(storage_path('archives/tmp/'));

        foreach ($files as $name => $file)
        {
            /** Skipping all subfolders */
            if (!$file->isDir()) {
                $filePath = $file->getRealPath();

                /** extracting filename with substr/strlen */
                $relativePath = '' . substr($filePath, strlen($path) -5);
                $zip->addFile($filePath, $relativePath);
            }
        }
        $zip->close();

        /** Include certificate to local monitor  */
        file_put_contents(storage_path('archives/monitor/' . $cert->id . '.cer'), $publicKey);

        File::delete(storage_path('archives/tmp/' . 'cert.csr'));
        File::delete(storage_path('archives/tmp/' . 'cert.cer'));

        return redirect()->route('admin.certs.index');
    }

    public function edit(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_edit'), 403);

        return view('admin.certs.edit', compact('cert'));
    }

    public function update(UpdateSigningCertificateRequest $request, Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_edit'), 403);

        $cert->update($request->all());

        return redirect()->route('admin.certs.index');
    }

    public function show(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_show'), 403);

        return view('admin.certs.show', compact('cert'));
    }

    public function destroy(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_delete'), 403);

        $cert->delete();

        return back();
    }

    public function massDestroy(MassDestroySigningCertificateRequest $request)
    {
        Cert::whereIn('id', request('ids'))->delete();

        return response(null, 204);
    }
}
