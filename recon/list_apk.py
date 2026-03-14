import zipfile, sys
z = zipfile.ZipFile('work/APNWidgetBaseRoot_ATT.apk')
for f in z.namelist():
    info = z.getinfo(f)
    print(f'{info.file_size:8d}  {f}')
