<?php

namespace App\Http\Controllers;

use App\Services\CommandService;

class DiagnosticsController
{
    #[Route("/ping", methods: ["GET"])]
    public function ping($host)
    {
        return CommandService::runPing($host);
    }

    #[Route("/ping/safe", methods: ["GET"])]
    public function pingSafe($host)
    {
        return CommandService::runPingSafe($host);
    }
}
