<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Params;
use App\Cert;
use File;

class KeyMatcherCertificateController extends Controller
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
        //
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

        /** Check if csr/cert/key are in DB. */
        if($cert->certificateServerRequest != null){
          $csr_status = 'Found';
        } else {
          $csr_status = 'Not found';
        }
        if($cert->publicKey != null){
          $cert_status = 'Found';
        } else {
          $cert_status = 'Not found';
        }
        if($cert->privateKey != null){
          $key_status = 'Found';
        } else {
          $key_status = 'Not found';
        }

        /** Checks if a private key matches certificate. */
        $keyMatchesCert = openssl_x509_check_private_key($cert->publicKey, $cert->privateKey);

        if($keyMatchesCert === true){
            $keyMatchesCert = 'YES';
          } else {
            $keyMatchesCert = 'NO';
          }
          file_put_contents(storage_path('archives/tmp/') . 'temp.csr', $cert->certificateServerRequest);
          file_put_contents(storage_path('archives/tmp/') . 'temp.cer', $cert->publicKey);

          $certSHA2sum = shell_exec("openssl x509 -in archives/tmp/temp.cer -pubkey -noout -outform pem | sha256sum 2>&1");
          $csrSHA2sum = shell_exec("openssl req -in archives/tmp/temp.csr -pubkey -noout -outform pem | sha256sum 2>&1");

          if($certSHA2sum === $csrSHA2sum){
            $certMatchesCSR = 'YES';
          } else {
            $certMatchesCSR = 'NO';
          }

          File::delete(storage_path('archives/tmp/') . 'temp.csr');
          File::delete(storage_path('archives/tmp/') . 'temp.cer');  

        return view('admin.keymatcher.show', compact(
            'id',
            'params',
            'subjectCommonName',
            'extensionsSubjectAltName',
            'csr_status',
            'cert_status',
            'key_status',
            'keyMatchesCert',
            'certMatchesCSR',
            'certSHA2sum',
            'csrSHA2sum'
        ));

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
