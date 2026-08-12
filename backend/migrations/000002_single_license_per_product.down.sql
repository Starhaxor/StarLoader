alter table licenses
    drop constraint if exists licenses_user_product_unique;
