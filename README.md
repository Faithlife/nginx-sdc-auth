SDC authentication module
=========================

Produces signatures for authenticated requests to Joyent SmartDC services, e.g. Manta.

```nginx
  server {
    listen     8000;

    location / {
      proxy_pass https://us-east.manta.joyent.com;

      sdc_key_path path_to_private_key;
      sdc_key_id public_key_id;
      sdc_user sdc_user;

      proxy_set_header Authorization $sdc_authorization;
      proxy_set_header Date $sdc_date;
    }
  }
```

Credits
=======
Based on [ngx_aws_auth](https://github.com/anomalizer/ngx_aws_auth) by Arvind Jayaprakash.

License
=======
This project uses the same license as ngnix does i.e. the 2 clause BSD / simplified BSD / FreeBSD license.
