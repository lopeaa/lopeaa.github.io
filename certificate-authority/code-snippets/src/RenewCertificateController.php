<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Cert;
use App\Params;
use File;
use ZipArchive;

class RenewCertificateController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $cert = Cert::where('id', $request->id)->get()->first();
        $config = '/usr/lib/ssl/openssl.cnf';

        /** Clean DNS: entries in ca.cnf */
        shell_exec("sudo /opt/subjectAltNameRemoval.sh 2>&1");

        /** Open ca.cnf, insert extensionsSubjectAltName and save ca.cnf */
        $insertSAN = file_get_contents($config);
        $insertSAN = str_replace("DNS:", $cert->extensionsSubjectAltName, $insertSAN);
        file_put_contents($config, $insertSAN);
        unset($insertSAN);

        /** Arguments pass to the CSR */
        $configArgs = array(
            'config' => $config,
            'encrypt_key' => false,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'subjectAltName' => $cert->extensionsSubjectAltName, // Not needed since it is hardcoded (above) in config file.
            'digest_alg' => $cert->signatureTypeSN,
            'x509_extensions' => $cert->extensionsExtendedKeyUsage
          );

        $serialNumber = random_int(160000000001, 170000000001); // serial for external CSR in Decimal format.
        $serialNumberHex = dechex($serialNumber); // serial for external CSR in Hexadecimal format.
        $cacert = file_get_contents('/opt/ca/cacert.pem');
        $pkeyid = array(file_get_contents('/opt/ca/private/cakey.pem'), $request->password );

        /** Sign csr from DB */
        $csr_sign = openssl_csr_sign($cert->certificateServerRequest , $cacert, $pkeyid, $request->validityPeriod, $configArgs, $serialNumber);

        /** Export signed certificate to string variable. */
        openssl_x509_export($csr_sign, $publicKey);

        /** Replace publickey for monitoring */
        File::delete(storage_path('archives/monitor/' . $cert->id . '.cer'));
        file_put_contents(storage_path('archives/monitor/' . $cert->id . '.cer'), $publicKey);

        /** Update archive/keypairs archive with new certificate */
        $zipFile = $cert->id . '.zip';

        $zip = new ZipArchive();
        $path = storage_path('archives/keypairs/');
        $zip->open($path . $zipFile, ZipArchive::CREATE);
        //$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));
        $zip->addFile(storage_path('archives/monitor/' . $cert->id . '.cer'), $cert->id . '.cer');
        $zip->close();

        shell_exec("sudo /opt/subjectAltNameRemoval.sh 2>&1");

        /** Certificate parser */
        $certParser = openssl_x509_parse($publicKey);

        /** DB updates */
        Cert::where('id', $cert->id)->update(['expiryDate' => $request->validityPeriod]);
        Cert::where('id', $cert->id)->update(['serialNumber' => $serialNumber]);
        Cert::where('id', $cert->id)->update(['serialNumberHex' => $serialNumberHex]);
        Cert::where('id', $cert->id)->update(['publicKey' => $publicKey]);
        Cert::where('id', $cert->id)->update(['p12' => null]);
        Cert::where('id', $cert->id)->update(['validFrom' => $certParser['validFrom']]);
        Cert::where('id', $cert->id)->update(['validTo' => $certParser['validTo']]);
        Cert::where('id', $cert->id)->update(['validFrom_time_t' => $certParser['validFrom_time_t']]);
        Cert::where('id', $cert->id)->update(['validTo_time_t' => $certParser['validTo_time_t']]);
        Cert::where('id', $cert->id)->update(['hash' => $certParser['hash']]);
        Cert::where('id', $cert->id)->update(['extensionsSubjectKeyIdentifier' => $certParser['extensions']['subjectKeyIdentifier']]);
        Cert::where('id', $cert->id)->update(['extensionsAuthorityKeyIdentifier' => $certParser['extensions']['authorityKeyIdentifier']]);
        Cert::where('id', $cert->id)->update(['status' => 'Valid']);

        return redirect()->route('admin.certs.index')->with('success', "Certificate successfully renewed.");
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $params = Params::all();
        $cert = Cert::where('id', $id)->get()->first();
        $subjectCommonName = $cert->subjectCommonName;
        $extensionsSubjectAltName = $cert->extensionsSubjectAltName;

        if ($cert->certificateServerRequest == null OR $cert->privateKey == null OR $cert->status == 'Revoked'){

            return redirect()->route('admin.certs.index')->with('error',"Keys not found. Check if Request (CSR) and Private keys exist and match OR if certificate is Revoked.");

        } elseif ($cert->issuerCN !== 'LIQUABit Root CA') { // Extract issuer from cert ca.cert.cert nad meke it dynamic.

            return redirect()->route('admin.certs.index')->with('error', "Issuer mismatch. It seems that this certificate has been issued by: {$cert->issuerCN}");

       } else {

            return view('admin.renew.show', compact('id', 'params', 'subjectCommonName', 'extensionsSubjectAltName'));
        }
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
}
