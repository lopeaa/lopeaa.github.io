<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Response;

class DownloadArchiveController extends Controller
{
    function downloadArchive($id){

            $headers = array('Content_Type: application/x-download');
            return Response::download(storage_path('archives/keypairs/' . $id . '.zip'), $id . '.zip', $headers);
    }

    function downloadCA(){

        $headers = array('Content_Type: application/x-download');
        return Response::download(storage_path('archives/cert.ca.cer'), 'cert.ca.cer', $headers);
}

    function downloadCRL(){

        $headers = array('Content_Type: application/x-download');
        return Response::download(storage_path('archives/ca-g2.crl'), 'ca-g2.crl', $headers);
    }


}
