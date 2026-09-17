<?php
// A small, self-contained Laravel-shaped routes file with a handful of
// genuine vulnerabilities and their safe counterparts, checked into the
// repo so eval/labels.json's PHP entries are reproducible without an
// external download -- the same role rust_demo/main.rs and
// csharp_demo/Program.cs play for their languages.
//
// This is a fixture for the rule library and call graph, not a Laravel
// project that runs: it is never booted, only parsed by tree-sitter and
// scanned by Semgrep, the same way the other *_demo fixtures are.
//
// Both PHP entry-point signals this tool recognises are exercised here:
// /ping is wired through a #[Route(...)] attribute directly on the
// controller method (DiagnosticsController.php), /users through this
// routes file's own Route::get() facade call naming a [Controller::class,
// 'method'] pair -- the one route-registration call in this project whose
// handler almost always lives in a different file than the registration
// itself.
Route::get('/users', [UserController::class, 'show']);
Route::get('/users/safe', [UserController::class, 'showSafe']);
