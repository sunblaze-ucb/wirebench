
## Downloading images for cuttlefish
Instructions adapted from https://source.android.com/docs/devices/cuttlefish/get-started --

To download the correct images, go to
https://ci.android.com/builds/branches/aosp-android13-gsi/grid?legacy=1 -- then choose one of the
builds under `aosp_cf_arm64_phone` and `aosp_cf_x86_64_phone`. Download the
`aosp_cf_x86_64_phone-img-<BUILD_NUMBER>.zip` file into the `x86` folder and
`aosp_cf_arm64_phone-img-<BUILD_NUMBER>.zip` file into the `arm` folder. Make sure to also download
the corresponding `cvd-host_package.tar.gz` for each as well. 

## Running ansible
Create an `ansible/inventory.ini` file in line with the template in `ansible`.

```
CF_ARCH=arm CUTTLEFISH_IMAGE_ZIP=aosp_cf_arm64_phone-img-15067704.zip ansible-playbook -i ansible/inventory.ini ansible/playbook.yml
```

This should get cuttlefish set up. You'll then want to SSH tunnel both the default ADB and Frida
ports from the machine that you want to do the analysis from:
```
ssh -L 6520:localhost:6520 -L 27042:localhost:27042 <USER_ID>@<IP_ADDRESS> -N
```

Running `adb devices` on this machine should then be able to interface with the virtual cuttlefish
device.
