alter table licenses
    add constraint licenses_user_product_unique unique (user_id, product);
