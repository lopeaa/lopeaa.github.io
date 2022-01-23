<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Cert;
use App\Params;
use File;

class RevokeCertificateController extends Controller
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
        $certFile = storage_path('archives/tmp/' . $request->id . '.cer');
        $password = $request->password;
        $crlFile = storage_path('archives/ca-g2.crl');

        file_put_contents(storage_path('archives/tmp/' . $request->id . '.cer'), $cert->publicKey);

        $revoke = shell_exec("sudo openssl ca -config $config -revoke $certFile -key $password -batch 2>&1");
        $revoked = substr($revoke, -18, 17);
        //dd($revoke, $revoked);
        if($revoked == 'Data Base Updated'){

            File::delete(storage_path('archives/tmp/' . $request->id . '.cer'));
            File::delete(storage_path('archives/keypairs/' . $request->id . '.zip'));
            File::delete(storage_path('archives/monitor/' . $request->id . '.cer'));
            File::delete(storage_path('archives/p12/' . $request->id . '.p12'));

            Cert::where('id', $request->id)->update(['status' => 'Revoked']);
            Cert::where('id', $request->id)->update(['revokedReason' => $request->revokedReason]);

            shell_exec("sudo openssl ca -gencrl -config $config -key $request->password -out $crlFile -batch 2>&1");

            return redirect()->route('admin.certs.index')->with('success','Successfully revoked.');

        } else {

            return redirect()->route('admin.certs.index')->with('error', " Trace: {$revoke}");
        }

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


        /** Return error if the certificate can´t be revoked. */
        if($cert->status == 'Revoked')
            {
                return redirect()->route('admin.certs.index')->with('error','Certificate is already revoked.');

            } elseif ($cert->status == 'Expired')
            {
                return redirect()->route('admin.certs.index')->with('error','Certificate is expired.');

            } elseif ($cert->publicKey == null) {

                return redirect()->route('admin.certs.index')->with('error','Certificate not found.');

            } else {

                return view('admin.revoke.show', compact('id', 'params', 'subjectCommonName', 'extensionsSubjectAltName'));
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
