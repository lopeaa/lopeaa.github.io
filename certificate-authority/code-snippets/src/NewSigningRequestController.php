<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\MassDestroyNewCertificateRequest;
use App\Http\Requests\StoreNewCertificateRequest;
use App\Http\Requests\UpdateNewCertificateRequest;
use App\Cert;
use App\Params;
use File;
use ZipArchive;

class NewSigningRequestController extends Controller
{

    public function create()
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

        $params = Params::all();

        return view('admin.certs.new-req.create', compact('params'));
    }

    public function store(StoreNewCertificateRequest $request)
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

        /** Separate CN and SANs. */
        $commonName = explode(";", $request->subjectCommonName);
		$subjectCommonName = $commonName[0]; /** separated cn */
        $extensionsSubjectAltName = explode(",", ("DNS:".implode(",DNS:", $commonName)));
        $extensionsSubjectAltName = implode(",", $extensionsSubjectAltName); // Separated SANs

        /** Extra data */
        $config = '/usr/lib/ssl/openssl.cnf';
        $dn = array(
            "countryName" => 'ES',
            "stateOrProvinceName" => 'Madrid',
            "localityName" => 'Madrid',
            "organizationName" => $request->subjectOrganization,
            "organizationalUnitName" => $organizationUnitName,
            "commonName" => $subjectCommonName
            //"emailAddress" => $request->emailAddress
        );
        /** Populate ca.cnf file with DNS: entries. */
        $configFile = file_get_contents($config);
        $configFile = str_replace("DNS:", $extensionsSubjectAltName, $configFile);
        file_put_contents($config, $configFile);
        unset($configFile);

        /** Data to be passed to the CSR. */
        $configArgs = array(
            'config' => $config,
            'encrypt_key' => false,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'subjectAltName' => $extensionsSubjectAltName,
            'signatureTypeSN' => $request->signatureTypeSN );

        /** Generate CSR and his corresponding Private Key. */
        $keygen = openssl_pkey_new();
        $csrgen = openssl_csr_new($dn, $keygen, $configArgs);

        /** Export Private Key and CSR to string. Also, save it to storage_path/tmp */
        openssl_pkey_export($keygen, $privateKey);
        openssl_csr_export($csrgen, $certificateServerRequest);
        file_put_contents(storage_path('archives/tmp/' . 'cert.csr'), $certificateServerRequest);
        file_put_contents(storage_path('archives/tmp/' . 'cert.key'), $privateKey);

        /** Clear DNS: entries in ca.cnf file. */
        shell_exec("sudo /opt/subjectAltNameRemoval.sh 2>&1");

        /** Create records in DB.*/
           $cert =  Cert::create([
                'subjectCommonName' => $subjectCommonName,
                'subjectOrganization' => $request->subjectOrganization,
                'extensionsExtendedKeyUsage' => $request->extensionsExtendedKeyUsage,
                'signatureTypeSN' => $request->signatureTypeSN,
                'extensionsSubjectAltName' => $extensionsSubjectAltName,
                'certificateServerRequest' => $certificateServerRequest,
                'privateKey' => $privateKey
                //'emailAddress' => $request->emailAddress
                ]);
            $cert->save();
        /** Zip the .cer and .key saved in storage_path/tmp and move it to storage_path/archives. */
        $zipFile = $cert->id . '.zip';
        $zip = new ZipArchive();
        $path = storage_path('archives/keypairs/');

        $zip->open($path . $zipFile, ZipArchive::CREATE);

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
                //$zip->setMtimeName($path . $zipFile, mktime(0,0,0,12,25,2019));
                //$zip->setEncryptionName($zipFile, ZipArchive::EM_AES_256, '1234');
            }
        }
        $zip->close();

        File::delete(storage_path('archives/tmp/' . 'cert.csr'));
        File::delete(storage_path('archives/tmp/' . 'cert.key'));

        return redirect()->route('admin.certs.index');
    }

    public function edit(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_edit'), 403);

        return view('admin.certs.edit', compact('cert'));
    }

    public function update(UpdateNewCertificateRequest $request, Cert $cert)
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

    public function massDestroy(MassDestroyNewCertificateRequest $request)
    {
        Cert::whereIn('id', request('ids'))->delete();

        return response(null, 204);
    }
}
