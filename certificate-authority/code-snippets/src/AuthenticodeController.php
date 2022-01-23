<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\MassDestroyCertificateRequest;
use App\Http\Requests\StoreCertificateRequest;
use App\Http\Requests\UpdateCertificateRequest;
use App\Cert;


class AuthenticodeController extends Controller
{
    public function index()
    {
        abort_unless(\Gate::allows('certificate_access'), 403);

        $certsNumber = Cert::all()->count();
        $certs = Cert::all();

        $certs_status_blank = Cert::where('status', '=', null)->count();
        $certs_status_valid = Cert::where('status', '=', 'Valid')->count();
        $certs_status_expiring = Cert::where('status', '=', 'Expiring')->count();
        $certs_status_expired = Cert::where('status', '=', 'Expired')->count();
        $certs_status_revoked = Cert::where('status', '=', 'Revoked')->count();
        //dd($certs);
        return view('admin.certs.index', compact('certs',
                                                'certsNumber',
                                                'certs_status_blank',
                                                'certs_status_valid',
                                                'certs_status_expiring',
                                                'certs_status_expired',
                                                'certs_status_revoked'));
    }

    public function create()
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

        return view('admin.certs.create');
    }

    public function store(StoreCertificateRequest $request)
    {
        abort_unless(\Gate::allows('certificate_create'), 403);

        $cert = Cert::create($request->all());

        return redirect()->route('admin.certs.index');
    }

    public function edit(Cert $cert)
    {
        abort_unless(\Gate::allows('certificate_edit'), 403);

        return view('admin.certs.edit', compact('cert'));
    }

    public function update(UpdateCertificateRequest $request, Cert $cert)
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

    public function massDestroy(MassDestroyCertificateRequest $request)
    {
        Cert::whereIn('id', request('ids'))->delete();

        return response(null, 204);
    }
}
