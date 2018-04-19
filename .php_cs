<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__ . '/lib')
    ->in(__DIR__ . '/tests')
;

return PhpCsFixer\Config::create()
    ->setRules([
        '@Symfony' => true,
        // 1. ignored rules from @Symfony
        'blank_line_after_opening_tag' => false,
        'blank_line_before_statement' => false,
        'cast_spaces' => false,
        'concat_space' => ['spacing' => 'one'],
        'phpdoc_align' => false,
        'phpdoc_annotation_without_dot' => false,
        'phpdoc_indent' => false,
        'phpdoc_separation' => false,
        'phpdoc_summary' => false,
        'single_blank_line_before_namespace' => false,
        'single_quote' => false,
        'trailing_comma_in_multiline_array' => false,
        'yoda_style' => false,
        // 2. additional rules
        'array_syntax' => ['syntax' => 'short'],
        'ordered_imports' => true,
    ])
    ->setFinder($finder)
;
