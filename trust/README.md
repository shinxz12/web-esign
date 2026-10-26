# Trust store mặc định

Chứng thư CA công khai của Việt Nam, đóng kèm ảnh triển khai. Lần chạy đầu
chúng được chép sang `$WEBSIGNER_DATA/trust` nếu thư mục đó còn rỗng; sau đó
người vận hành toàn quyền thêm/bớt mà không bị ghi đè.

| Tệp | Loại |
|---|---|
| `mic-national-root-ca.cer` | root, MIC National Root CA (2008–2040) |
| `vietnam-national-root-ca-2014-2039.cer` | root, Vietnam National Root CA |
| `viettel-ca-2010-2015.cer` | trung gian Viettel-CA (đã hết hạn) |
| `viettel-ca-2015-2020.cer` | trung gian Viettel-CA (đã hết hạn) |
| `viettel-ca-rs-2022-2027.cer` | trung gian Viettel-CA RS |

Chỉ CA **tự ký** mới thành trust anchor; CA trung gian chỉ dùng để nối chuỗi.
Muốn hỗ trợ thêm CA nào (VNPT-CA, FPT-CA, BKAV, Nacencomm…) thì bỏ chứng thư
của họ vào đây hoặc vào volume `/data/trust`.

Đây là chứng thư công khai, không chứa khoá riêng.
