<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\MassDestroyCertificateKeyPair;
use App\Http\Requests\StoreCertificateKeyPair;
use App\Http\Requests\UpdateCertificate;
use App\Exceptions\WrongCaKeyPasswordException;
use Spatie\SslCertificate\SslCertificate;
//use RealRashid\SweetAlert\Facades\Alert;
use App\Cert;
use App\Params;
use File;
use ZipArchive;
use Carbon\Carbon;

class CertificatesController extends Controller
{
    public function index()
    {
        abort_unless(\Gate::allows('certificate_access'), 403);

        $certsNumber = Cert::all()->count();
        $certs = Cert::all();

        /** Recalculate the expiry date and update */
        foreach ($certs as $cert) {

            $id = $cert->id;

            /** calculate days diff between cert and today and update DB. */
            if ($cert->validTo_time_t != null){
             $certificate = SslCertificate::createFromString($cert->publicKey);
             //$today = Carbon::today();
             $validToDate = $certificate->expirationDate();
             $expiryDate = (string)$validToDate->diffInDays(today(), false);
             $isValid = $certificate->isValid();
             $isExpired = $certificate->isExpired();

             /**  Calculate days to expire. */
              $isExpiringInterval = $validToDate->copy()->subDays(60);
              $isExpiring = today()->isBetween($isExpiringInterval, $validToDate);
                
             /** Update diff in day. */
             Cert::where('id', $id)->update(['expiryDate' => $expiryDate]);
           }

           if (empty($cert->publicKey)){

               $status = null;
               Cert::where('id', $id)->update(['status' => $status]);

           } elseif ($isExpired === true) {

               $status = 'Expired';
               Cert::where('id', $id)->update(['status' => $status ]);

             /** Ones cert is expired, it is deleted so that it is not scan with expiry check script. */
             FILE::delete(storage_path('archives/keypairs/' . $id . '.zip'));
             FILE::delete(storage_path('archives/monitor/' . $id . '.cer'));
             FILE::delete(storage_path('archives/p12/' . $id . '.p12'));

            } elseif ($isExpiring === true && $cert->status != 'Revoked'){

                $status = 'Expiring';
                Cert::where('id', $id)->update(['status' => $status]);
 
            } elseif ($cert->status === 'Revoked'){

                $status = 'Revoked';
                Cert::where('id', $id)->update(['status' => $status]);

            } elseif ($isValid === true){

               $status = 'Valid';
               Cert::where('id', $id)->update(['status' => $status]);

             } else {
               $status = $cert->status; 
               Cert::where('id', $id)->update(['status' => $status]);
            }
           }

        /** Chart */
        $certs_status_blank = Cert::where('status', '=', null)->count();
        $certs_status_valid = Cert::where('status', '=', 'Valid')->count();
        $certs_status_expiring = Cert::where('status', '=', 'Expiring')->count();
        $certs_status_expired = Cert::where('status', '=', 'Expired')->count();
        $certs_status_revoked = Cert::where('status', '=', 'Revoked')->count();


        return view('admin.certs.index', compact('certs',
                                                'certsNumber',
                                                'certs_status_blank',
                                                'certs_status_valid',
                                                'certs_status_expiring',
                                                'certs_status_expired',
                                                'certs_status_revoked' ));
    }

    public function create()
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

        $params = Params::all();

        return view('admin.certs.new-cert.create', compact('params'));
    }

    public function store(StoreCertificateKeyPair $request)
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

            /** Separate CN and SANs. */
            $commonName = explode(";", $request->subjectCommonName);
			$subjectCommonName = $commonName[0];
            $extensionsSubjectAltName = explode(",", ("DNS:".implode(",DNS:", $commonName)));
            $extensionsSubjectAltName = implode(",", $extensionsSubjectAltName);

            /** Configuration file. */
            $config = '/usr/lib/ssl/openssl.cnf';

            /** Data needed to populate the certificate signed by this CA. email can´t be empty so if it is empty "emailAddress" is not included. */
            if($request->email != ''){
                  $dn = array(
                     "countryName" => 'ES',
                     "stateOrProvinceName" => 'Madrid',
                     "localityName" => 'Madrid',
                     "organizationName" => $request->subjectOrganization,
                     "organizationalUnitName" => $organizationUnitName,
                     "commonName" => $subjectCommonName,
                     "emailAddress" => $request->email
                     );
             } else {
                  $dn = array(
                     "countryName" => 'ES',
                     "stateOrProvinceName" => 'Madrid',
                     "localityName" => 'Madrid',
                     "organizationName" => $request->subjectOrganization,
                     "organizationalUnitName" => $organizationUnitName,
                     "commonName" => $subjectCommonName
                     //"emailAddress" => null
                     );
               }

            /** Clean DNS entries. */
            shell_exec("sudo /opt/subjectAltNameRemoval.sh 2>&1"); /** Clear DNS entries script. */
            $configFile = file_get_contents($config);
            $configFile = str_replace("DNS:", $extensionsSubjectAltName, $configFile); /** Do replacements. */
            file_put_contents($config, $configFile);
            unset($configFile);

            /** Arguments to be passed to the CSR. */
            $configArgs = array(
                'config' => $config,
                'encrypt_key' => false,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'subjectAltName' => $request->extensionsSubjectAltName,
                'digest_alg' => $request->signatureTypeSN );

            /** Generate REQ and his corresponding Private Key. */
            $reqgen = openssl_csr_new($dn, $keygen, $configArgs);

            /** Export Private Key to string and save it to disk. */
            openssl_pkey_export($keygen, $privateKey);

            /** Export CSR to string and save it to disk. */
            openssl_csr_export($reqgen, $certificateServerRequest);

            /** Signing CSR. Location of CA Pub/Priv certificates. */
            $cacert = file_get_contents('/opt/ca/cacert.pem');
            $pkeyid = array(file_get_contents('/opt/ca/private/cakey.pem'), $request->password );
            $configArgs = array(
                    'config' => $config,
                    'encrypt_key' => false,
                    'private_key_bits' => (int)$request->keyLength,
                    'private_key_type' => OPENSSL_KEYTYPE_RSA,
                    'digest_alg' => $request->signatureTypeSN,
                    'x509_extensions' => $request->extensionsExtendedKeyUsage);

            /** Insert serial number. */
            $serialNumber = random_int(160000000001, 170000000001);

            /** Sign Certificate Server Request. */
            $certgen = openssl_csr_sign($certificateServerRequest , $cacert, $pkeyid, $request->validityPeriod, $configArgs, $serialNumber);

            /** Export signed certificate to string variable and save it to disk. */
            openssl_x509_export($certgen, $publicKey);

            /** Clean SAN DNS entries. */
            shell_exec("sudo /opt/subjectAltNameRemoval.sh 2>&1");

            /** Parse certificate data. */
            $certParser = openssl_x509_parse($publicKey);

            /** Include certificate parse data in request.  */
            $request['subjectCommonName'] = $certParser['subject']['CN'];
            $request['subjectContry'] = $certParser['subject']['C'];
            $request['subjectState'] = $certParser['subject']['ST'];
            $request['subjectOrganization'] = $certParser['subject']['O'];
            $request['subjectOrganizationUnit'] = $certParser['subject']['OU'];
            $request['hash'] = $certParser['hash'];
            $request['issuerCN'] = $certParser['issuer']['CN'];
            $request['issuerOrganization'] = $certParser['issuer']['O'];
            $request['issuerOrganizationUnit'] = $certParser['issuer']['OU'];
            $request['version'] = $certParser['version'];
            $request['serialNumber'] = $serialNumber;
            //$request['serialNumberHex'] = $serialNumberHex;
            $request['validFrom'] = $certParser['validFrom'];
            $request['validTo'] = $certParser['validTo'];
            $request['validFrom_time_t'] = $certParser['validFrom_time_t'];
            $request['validTo_time_t'] = $certParser['validTo_time_t'];
            $request['signatureTypeSN'] = $certParser['signatureTypeSN'];
            $request['signatureTypeLN'] = $certParser['signatureTypeLN'];
            $request['signatureTypeNID'] = $certParser['signatureTypeNID'];
            $request['purposes'] = null; // to be implemented.
            $request['extensionsBasicConstraints'] = $certParser['extensions']['basicConstraints'];
            $request['extensionsKeyUsage'] = $certParser['extensions']['keyUsage'];
            $request['extensionsExtendedKeyUsage'] = $certParser['extensions']['extendedKeyUsage'];
            $request['extensionsSubjectKeyIdentifier'] = $certParser['extensions']['subjectKeyIdentifier'];
            $request['extensionsAuthorityKeyIdentifier'] = $certParser['extensions']['authorityKeyIdentifier'];
            $request['extensionsSubjectAltName'] = $certParser['extensions']['subjectAltName'];
            $request['extensionsCrlDistributionPoints'] = $certParser['extensions']['crlDistributionPoints'];
            $request['certificateServerRequest'] = $certificateServerRequest;
            $request['publicKey'] = $publicKey;
            $request['privateKey'] = $privateKey;
            $request['status'] = 'Valid';
            $request['p12'] = null;

            /** Convert dates. */
            $validTo_time_t = date(DATE_RFC2822, $certParser['validTo_time_t']);
            $expiryDate = Carbon::parse(Carbon::now())->diffInDays($validTo_time_t);
            $request['expiryDate'] = $expiryDate;

            $cert = Cert::create($request->all());
            $cert->save();

            $cert = Cert::where('subjectCommonName', $subjectCommonName)->get()->last();

            file_put_contents(storage_path('archives/tmp/' . $cert->id . '.key'), $privateKey);
            file_put_contents(storage_path('archives/tmp/' . $cert->id .'.cer'), $publicKey);
            file_put_contents(storage_path('archives/tmp/' . $cert->id . '.csr'), $certificateServerRequest);

            /** If Monitor check enabled, include in /opt/certmon/ json.
             * Possible solution is to trigger the e-mail or just include the json data in the files.
            */


            /** end include in certmon */

            file_put_contents(storage_path('archives/monitor/' . $cert->id . '.cer'), $publicKey);

            /** Zip the .cer and .key saved in storage_path/tmp and move it to storage_path/archives. then, delete files. */
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

                    /** Extracting filename with substr/strlen */
                    $relativePath = '' . substr($filePath, strlen($path) -5);

                    $zip->addFile($filePath, $relativePath);
                }
            }
            $zip->close();


            File::delete(storage_path('archives/tmp/' . $cert->id . '.csr'));
            File::delete(storage_path('archives/tmp/' . $cert->id . '.cer'));
            File::delete(storage_path('archives/tmp/' . $cert->id . '.key'));

        //Alert::success('Certificate successfully created', 'Certificate keypair has been created', 'Success');
        return redirect()->route('admin.certs.index')->with('success', 'Certificate keypair created successfully.');
    }

    public function edit(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_edit'), 403);

        return view('admin.certs.edit', compact('cert'));
    }

    public function update(UpdateCertificate $request, Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_edit'), 403);

        /** Make a Keymatch before updating. */
        if ($request->filled(['certificateServerRequest','publicKey', 'privateKey']) && $cert->status != 'Revoked') {

            /** Check if PublicKey matches PrivateKey. */
            $keyMatches = openssl_x509_check_private_key($request->input('publicKey'), $request->input('privateKey'));

            /** Check if CSR matches PublicKey. */
                file_put_contents(storage_path('archives/tmp/') . 'csr.csr', $request->input('certificateServerRequest'));
                file_put_contents(storage_path('archives/tmp/') . 'cert.cer', $request->input('publicKey'));
                file_put_contents(storage_path('archives/tmp/') . 'key.key', $request->input('privateKey'));
                
                $certSHA2sum = shell_exec("openssl x509 -in archives/tmp/cert.cer -pubkey -noout -outform pem | sha256sum 2>&1");
                $csrSHA2sum = shell_exec("openssl req -in archives/tmp/csr.csr -pubkey -noout -outform pem | sha256sum 2>&1");

                if($certSHA2sum === $csrSHA2sum && $keyMatches === true){

                    $cert->update($request->all('certificateServerRequest'));
                    $cert->update($request->all('publicKey'));
                    $cert->update($request->all('privateKey'));
                    $cert->update($request->all('comments'));

                } else {

                    File::delete(storage_path('archives/tmp/') . 'csr.csr');
                    File::delete(storage_path('archives/tmp/') . 'cert.cer');
                    File::delete(storage_path('archives/tmp/') . 'key.key');
            
                    return redirect()->route('admin.certs.index')->with('error', 'Certificate and Private key don´t match');
                }

            /** Parse certificate data. */
            $certParser = openssl_x509_parse($request->input('publicKey'));
                $request['subjectCommonName'] = $certParser['subject']['CN'];
                $request['subjectContry'] = $certParser['subject']['C'];
                //$request['subjectState'] = $certParser['subject']['ST'];
                $request['subjectOrganization'] = $certParser['subject']['O'];
                //$request['subjectOrganizationUnit'] = $certParser['subject']['OU'];
                $request['hash'] = $certParser['hash'];
                $request['issuerCN'] = $certParser['issuer']['CN'];
                $request['issuerOrganization'] = $certParser['issuer']['O'];
                //$request['issuerOrganizationUnit'] = $certParser['issuer']['OU'];
                $request['version'] = $certParser['version'];
                $request['serialNumber'] = $certParser['serialNumber'];
                $request['serialNumberHex'] = $certParser['serialNumberHex'];
                $request['validFrom'] = $certParser['validFrom'];
                $request['validTo'] = $certParser['validTo'];
                $request['validFrom_time_t'] = $certParser['validFrom_time_t'];
                $request['validTo_time_t'] = $certParser['validTo_time_t'];
                $request['signatureTypeSN'] = $certParser['signatureTypeSN'];
                $request['signatureTypeLN'] = $certParser['signatureTypeLN'];
                $request['signatureTypeNID'] = $certParser['signatureTypeNID'];
                $request['purposes'] = null;
                $request['extensionsBasicConstraints'] = $certParser['extensions']['basicConstraints'];
                $request['extensionsKeyUsage'] = $certParser['extensions']['keyUsage'];
                $request['extensionsExtendedKeyUsage'] = $certParser['extensions']['extendedKeyUsage'];
                $request['extensionsSubjectKeyIdentifier'] = $certParser['extensions']['subjectKeyIdentifier'];
                $request['extensionsAuthorityKeyIdentifier'] = $certParser['extensions']['authorityKeyIdentifier'];
                $request['extensionsSubjectAltName'] = $certParser['extensions']['subjectAltName'];
                $request['extensionsCrlDistributionPoints'] = $certParser['extensions']['crlDistributionPoints'];
                $request['certificateServerRequest'] = $request->input('certificateServerRequest');
                $request['publicKey'] = $request->input('publicKey');
                $request['privateKey'] = $request->input('privateKey');
                $request['p12'] = null;

                /** Convert dates. */
                $validTo_time_t = date(DATE_RFC2822, $certParser['validTo_time_t']);
                $expiryDate = Carbon::parse(Carbon::now())->diffInDays($validTo_time_t, false); /** in days */

                $request['expiryDate'] = $expiryDate;

                /** Calculate status: Valid,Expiring, Expired. */
                if($expiryDate > 0) {
                    $request['status'] = 'Valid';
                }
                elseif($expiryDate >= 90) {
                    $request['status'] = 'Expiring';
                }
                elseif($expiryDate < 0) {
                    $request['status'] = 'Expired';
                }

                $cert->update($request->all(
                    'subjectCommonName',
                    'subjectContry',
                    //'subjectState',
                    'subjectOrganization',
                    //'subjectOrganizationUnit',
                    'hash',
                    'issuerCN',
                    'issuerOrganization',
                    //'issuerOrganizationUnit',
                    'version',
                    'serialNumber',
                    'serialNumberHex',
                    'validFrom',
                    'validTo',
                    'validFrom_time_t',
                    'validTo_time_t',
                    'expiryDate',
                    'signatureTypeSN',
                    'signatureTypeLN',
                    'signatureTypeNID',
                    'purposes',
                    'extensionsBasicConstraints',
                    'extensionsKeyUsage',
                    'extensionsExtendedKeyUsage',
                    'extensionsSubjectKeyIdentifier',
                    'extensionsSubjectAltName',
                    'extensionsSubjectAltName',
                    'extensionsCrlDistributionPoints',
                    'certificateServerRequest',
                    'publicKey',
                    'privateKey',
                    'status',
                    'p12',
                ));

        /** Include certificate to local monitor  */
        file_put_contents(storage_path('archives/monitor/' . $cert->id . '.cer'), $request->publicKey);

        /** Zip the .cer and .key saved in storage_path/tmp and move it to storage_path/archives. */
        $zipFile = $cert->id . '.zip';
        $zip = new ZipArchive();
        $path = storage_path('archives/keypairs/');

        $zip->open($path . $zipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE);

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
        file_put_contents(storage_path('archives/monitor/' . $cert->id . '.cer'), $request->publicKey);

        File::delete(storage_path('archives/tmp/') . 'csr.csr');
        File::delete(storage_path('archives/tmp/') . 'cert.cer');
        File::delete(storage_path('archives/tmp/') . 'key.key');

            return redirect()->route('admin.certs.index')->with('success','Updated successfully.');

        } elseif ($cert->status === 'Revoked'){

            return redirect()->route('admin.certs.index')->with('error','Certificate is Revoked and can´t be updated.');

        } else {
                //Alert::error('Error Updating', 'Data don´t match or has not been provided.', 'error')->persistent('close');
                return redirect()->route('admin.certs.index')->with('error','Error updating. Check if public and private key matches.');
        }
    }

    public function show(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_show'), 403);

        /** Convert dates validFrom and validTo to show them properly in view. */
        $certs = Cert::all();

        $validFrom_time_t = date(DATE_RFC2822, $cert->validFrom_time_t);
        $validTo_time_t = date(DATE_RFC2822, $cert->validTo_time_t);
        $created_at = $cert->created_at;

        return view('admin.certs.show', compact(
            'cert',
            'validFrom_time_t', 
            'validTo_time_t',
            'created_at'
        ));
    }

    public function destroy(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_delete'), 403);

        $cert->delete();
        /** Delete file from storage. This file is used by the local monitoring script */
        //Alert::success('Deleted Successfully', 'All data related to this certificate has been deleted.', 'Success');
        File::delete(storage_path('archives/monitor/' . $cert->id .'.cer'));
        File::delete(storage_path('archives/keypairs/' . $cert->id .'.zip'));

        return back();
    }

    public function massDestroy(MassDestroyCertificateKeyPair $request)
    {
        Cert::whereIn('id', request('ids'))->delete();

        return response(null, 204);
    }

}
