<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Cert;

class ConverterController extends Controller
{

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
    }


    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Request
     * @return \Illuminate\Http\Response
     */
    public function create($id)
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
        $p12Args = array(
            'friendly_name' => $cert->subjectCommonName,
            'extracerts' => storage_path('archives/','cert.ca.cer')
        );

        /** Export it to string format in order to insert it in database and to file to back it up in archives/p12/ */
        openssl_pkcs12_export($cert->publicKey, $p12String, $cert->privateKey, $request->password, $p12Args);
        openssl_pkcs12_export_to_file($cert->publicKey, storage_path('archives/p12/' . $request->id . '.p12'), $cert->privateKey, $request->password, $p12Args);

        /** Update database field 'p12' */
        Cert::where('id', $request->id)->update(['p12' => $p12String]);

        $headers = array('Content_Type: application/x-download',);
        return response()->download(storage_path('archives/p12/' . $request->id . '.p12'), $request->id . '.p12', $headers);
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function Show($id)
    {
        $cert = Cert::where('id', $id)->get()->first();
        $subjectCommonName = $cert->subjectCommonName;

        if ($cert->publicKey == null OR $cert->privateKey == null){

            return redirect()->route('admin.certs.index')->with('error','Keys not found. Check if Public and Private keys exist and match.');

        } else {

            return view('admin.converter.show', compact('id', 'subjectCommonName'));
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
        dd('Edit');
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
        dd('Update');
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        dd('Destroy');
    }
}
