UPDATE portal_design_templates
SET html_template = replace(html_template, '{{voucher_form}}', '{{product_items}}' || E'\n' || '{{voucher_form}}'),
    updated_at = now()
WHERE html_template IS NOT NULL
  AND html_template NOT LIKE '%{{product_items}}%'
  AND html_template LIKE '%{{voucher_form}}%';
