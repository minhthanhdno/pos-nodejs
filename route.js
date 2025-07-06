'use strict'
const fs = require('fs');
const sql = require('mssql');
const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const underscore = require('underscore');
const { parseString } = require('xml2js'); // Thêm thư viện xml2js để xử lý XML
const path = require('path');
const async = require('async');
const request = require("request");
const { server } = require("./configs.json");
const { emitEvent, getDataFromSTPService } = require("./API.js");
const xml2js = require('xml2js');

module.exports = function (app) {
	'use strict';
	//main router
	const router = express.Router();
	router.use(function (req, res, next) {
		for (let key in req.query) {
			if (req.query[key] == 'true') {
				req.query[key] = true;
			}
			if (req.query[key] == 'false') {
				req.query[key] = false;
			}
		}
		next();
	});
	app.use('/api', router);
	//get ent-token
	// Thay thế toàn bộ route GET thành cả GET và POST (nếu cần vẫn giữ GET cũ để tương thích)
router.route('/:database/token')
  .all(async function (req, res, next) { // .all cho phép cả GET và POST
    try {
      const database = req.params.database;
      // Ưu tiên body > header > query
      let username =
        (req.body && req.body.username) ||
        req.headers['username'] ||
        req.query.username;
      let password =
        (req.body && req.body.password) ||
        req.headers['password'] ||
        req.query.password;

      // Xử lý Basic Auth nếu có
      let authorization = req.headers.authorization;
      if (authorization && authorization.startsWith("Basic ")) {
        const decoded = Buffer.from(authorization.replace("Basic ", ""), 'base64').toString();
        const [user, pass] = decoded.split(':');
        if (user && pass) {
          username = user;
          password = pass;
        }
      }

      if (!database || !username || !password) {
        return res.status(400).send({ message: "Authorization is required" });
      }

      const url = server + database + "/gettoken/nodejs?username=" + encodeURIComponent(username) + "&password=" + encodeURIComponent(password);
      request(url, function (error, response, body) {
        if (error) return res.status(400).send({ message: error.message || error });
        if (body.indexOf("ERROR") >= 0) {
          return res.status(400).send({ message: body });
        }
        // KHÔNG dùng eval!
        let json;
        try {
          json = JSON.parse(body);
        } catch (e) {
          return res.status(400).send({ message: "Parse token error: " + e.message });
        }
        return res.send(json);
      });
    } catch (err) {
      return res.status(500).send({ message: "Server error: " + err.message });
    }
  });

	//logout
	router.route('/:database/logout').get(function (req, res, next) {
		const database = req.params.database;
		const token = req.headers['access-token'] || req.query.access_token;
		let url = server + database + "/logout?token=" + token;
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			return res.send(body);
		});
	});
	//userinfo
	router.route('/:database/userinfo').get(function (req, res, next) {
		let database = req.params.database;
		var token = req.headers['access-token'] || req.query.access_token;
		let url = server + database + "/userinfo?token=" + token;
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			return res.send(body);
		});
	});
	
	router.route('/:database/list/:id_list').get(function (req, res, next) {
		const database = req.params.database;
		const id_list = req.params.id_list;
		const token = req.headers['access-token'] || req.query.access_token;

		let url = server + database + "/list/" + id_list + "?token=" + token;
		let v_q;
		for (let q in req.query) {
			if (q !== "access_token") {
				v_q = req.query[q];
				if (v_q == true || v_q == "true") {
					v_q = "1"
				}
				if (v_q == false || v_q == "false") {
					v_q == "0"
				}
				url = url + "&" + q + "=" + encodeURI(v_q);
			}
		}
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
		});
	});




	////////////////////////

	router.route('/:database/list/:id_list').post(function (req, res, next) {
		const database = req.params.database;
		const id_list = req.params.id_list;
		const body = req.body;
		console.log("Body Insert111",body)
	
		const token = req.headers['access-token'] || req.query.access_token;
	
		let url = server + database + "/list/" + id_list + "?token=" + token;
		console.log('Request URL:', url);
		var options = {
			'method': 'POST',
			'url': url,
			'headers': {
			  'Content-Type': 'application/x-www-form-urlencoded'
			},
			form: body
		  };
		  request(options, function (error, response) {
			if (error)  return res.status(400).send({ message: error.message || error });
			let body = response.body;
			console.log("Body Insert",body)
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
			console.log("send",body);
		  });
		
	
	});

	//Lay danh sach mon an
	router.route('/:database/menu-items').get(function (req, res) {
  const database = req.params.database;
  const group_id = req.query.group_id || "ALL";
  const token = req.headers['access-token'] || req.query.token || "";

  if (!token) {
    return res.status(401).send({ message: "Thiếu token" });
  }

  // Xây dựng URL gọi đến WCF
  let url = `${server}${database}/menu-items?group_id=${encodeURIComponent(group_id)}&token=${token}`;

  // Thêm các tham số truy vấn khác nếu có
  for (let q in req.query) {
    if (q !== "token" && q !== "group_id") {
      let v_q = req.query[q];
      if (v_q === true || v_q === "true") v_q = "1";
      if (v_q === false || v_q === "false") v_q = "0";
      url += `&${q}=${encodeURIComponent(v_q)}`;
    }
  }

  // Gửi request đến WCF
  request(url, function (error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });

    if (body.includes("ERROR")) {
      return res.status(400).send({ message: body });
    }

    try {
      const json = JSON.parse(body);
      return res.send(json);
    } catch (e) {
      return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message });
    }
  });
});

// CreateVoucherMPBL
// Tạo phiếu bán hàng lẻ (mpbl)
router.post("/:database/voucher/mpbl/:stt_rec", (req, res) => {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.headers["access-token"] || req.query.access_token || "";

  // Chuẩn bị URL gọi sang WCF API
  const url = `http://localhost:1985/${database}/voucher/mpbl/${stt_rec}?token=${token}`;
  console.log("🔁 Gọi WCF API:", url);

  // Forward body nếu có (mặc định có thể là `{}`)
  const bodyData = JSON.stringify(req.body || {});

  // Gửi request POST tới WCF API
  request.post(
    {
      url: url,
      body: bodyData,
      headers: { "Content-Type": "application/json" },
    },
    (error, response, body) => {
      if (error) return res.status(500).send({ message: error.message });
      if (body.includes("ERROR")) {
        return res.status(400).send({ message: body });
      }
      try {
        const data = JSON.parse(body);
        res.send(data);

        // ==> LẤY CHÍNH XÁC ma_ban từ request hoặc response
        let ma_ban = req.body.ma_ban;
        if (!ma_ban && Array.isArray(data) && data[0] && data[0].ma_ban) {
          ma_ban = data[0].ma_ban;
        }
        const status = 1; // đang sử dụng
        const io = req.app.get('io');
        if (io && ma_ban) {
          io.emit('table_status_update', { ma_ban, status });
        }
      } catch (e) {
        if (!res.headersSent) {
          res.status(500).send({ message: "Lỗi xử lý JSON trả về", raw: body });
        }
      }
    }
  );
});


//Xử lý update động nhiều trường trong MPLB
router.put("/:database/voucher/mpbl/:stt_rec/update", (req, res) => {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.query.token || req.body.token || req.headers['access-token'] || "";

  // Dữ liệu update động (x-www-form-urlencoded hoặc JSON key-value)
  const updateFields = req.body; // Nếu dùng form, hoặc dùng Object.assign({}, req.body)

  // Gọi WCF API
  const request = require('request');
  request.put({
    url: `http://localhost:1985/${database}/voucher/mpbl/${stt_rec}/update?token=${token}`,
    form: updateFields
  }, (error, response, body) => {
    if (error) return res.status(500).send({ message: error.message });
    if (body && body.includes("ERROR")) return res.status(400).send({ message: body });
    try {
      res.send(JSON.parse(body));


	  
    } catch (e) {
      res.status(500).send({ message: "Lỗi phân tích JSON", raw: body });
    }
  });
});

//update dong dpbl UpdateVoucherDPBL
router.put("/:database/voucher/dpbl/:stt_rec/update", (req, res) => {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token =
    req.query.token ||
    req.body.token ||
    req.headers["access-token"] ||
    "";

  const updateFields = req.body; // hỗ trợ cả JSON lẫn urlencoded (express đã parse)
  const headers = {};
  let requestOptions = {};

  // Nếu FE gửi JSON, thì gửi lên backend dạng application/json
  if (
    req.headers["content-type"] &&
    req.headers["content-type"].includes("application/json")
  ) {
    headers["content-type"] = "application/json";
    requestOptions = {
      url: `http://localhost:1985/${database}/voucher/dpbl/${stt_rec}/update?token=${token}`,
      body: JSON.stringify(updateFields),
      headers,
    };
  } else {
    // Nếu là form-urlencoded
    headers["content-type"] = "application/x-www-form-urlencoded";
    requestOptions = {
      url: `http://localhost:1985/${database}/voucher/dpbl/${stt_rec}/update?token=${token}`,
      form: updateFields,
      headers,
    };
  }

  require("request").put(requestOptions, (error, response, body) => {
    if (error)
      return res.status(500).send({ message: error.message || error });

    // Trả về lỗi dễ debug nếu backend báo lỗi
    if (body && body.includes("ERROR"))
      return res.status(400).send({ message: body });

    let result = {};
    try {
      result = JSON.parse(body);
    } catch (e) {
      return res.status(500).send({ message: "Lỗi phân tích JSON", raw: body });
    }

    // --- PHÁT SOCKET realtime nếu cần ---
    // Ví dụ: cập nhật món hoặc trạng thái tạm tính
    // Chỉ phát khi thành công, có trường hợp FE cần cập nhật bảng/phiếu ngay
    const io = req.app.get("io");
    if (io && result.status === "OK") {
      // Phát cho tất cả client đang mở app biết có cập nhật phiếu
      io.emit("voucher_dpbl_updated", {
        stt_rec,
        database,
        updateFields,
      });
    }

    res.send(result);
  });
});



//gettable
// Lấy danh sách bàn theo khu vực
router.route('/:database/tables').get(function (req, res) {
  const database = req.params.database;
  const ma_kv = req.query.ma_kv || "";        // Mã khu vực (nếu có)
  const token = req.headers['access-token'] || req.query.token || "";

  if (!token) {
    return res.status(401).send({ message: "Thiếu token" });
  }

  // Xây dựng URL gọi đến WCF
  let url = `${server}${database}/tables?token=${token}`;
  if (ma_kv) url += `&ma_kv=${encodeURIComponent(ma_kv)}`;

  // Thêm các tham số truy vấn khác nếu có (ngoại trừ token, ma_kv)
  for (let q in req.query) {
    if (q !== "token" && q !== "ma_kv") {
      let v_q = req.query[q];
      if (v_q === true || v_q === "true") v_q = "1";
      if (v_q === false || v_q === "false") v_q = "0";
      url += `&${q}=${encodeURIComponent(v_q)}`;
    }
  }

  // Gửi request đến WCF
  request(url, function (error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });

    if (body.includes("ERROR")) {
      return res.status(400).send({ message: body });
    }

    try {
      const json = JSON.parse(body);
      return res.send(json);
    } catch (e) {
      return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message });
    }
  });
});
//
//
//Lấy danh sách khu vực res_dmkv
router.get('/:database/areas', function(req, res) {
  const database = req.params.database;
  const token = req.query.token || req.headers['access-token'] || "";
  const url = `${server}${database}/areas?token=${token}`;
  require('request').get({ url }, function(error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });
    try {
      return res.send(JSON.parse(body));
    } catch (e) {
      return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message, raw: body });
    }
  });
});


//DPBL
// Gọi API thêm món vào phiếu dpbl
router.post("/:database/voucher/dpbl/:stt_rec", (req, res) => {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.headers["access-token"] || req.query.access_token || "";

  // WCF API endpoint
  const url = `http://localhost:1985/${database}/voucher/dpbl/${stt_rec}?token=${token}`;
  console.log("📦 Gọi WCF API AddItemToDPBL:", url);

  // Forward body dạng application/x-www-form-urlencoded
  const formData = new URLSearchParams(req.body).toString();

    request.post(
    {
      url: url,
      body: formData,
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    },
    (error, response, body) => {
      if (error) return res.status(500).send({ message: error.message });
      if (body.includes("ERROR")) {
        return res.status(400).send({ message: body });
      }
      try {
        const data = JSON.parse(body);
        res.send(data);

        let ma_ban = req.body.ma_ban;
        if (!ma_ban && Array.isArray(data) && data[0] && data[0].ma_ban) {
          ma_ban = data[0].ma_ban;
        }
        const io = req.app.get('io');
        if (io && ma_ban) {
          io.emit('order_update', { stt_rec, ma_ban, data });
        }
      } catch (e) {
        if (!res.headersSent) {
          res.status(500).send({ message: "Lỗi xử lý JSON trả về", raw: body });
        }
      }
    }
  );
});




//xu ly trang thai table
router.put('/:database/table/:ma_ban/status', function(req, res) { 
  const database = req.params.database;
  const ma_ban = req.params.ma_ban;
  const token = req.query.token || req.headers['access-token'] || "";
  const status = req.body.status; // Yêu cầu dùng body-parser
  if (typeof status === "undefined") {
    return res.status(400).send({ message: "Thiếu trường status!" });
  }

  // Build URL gọi sang WCF API cập nhật status (hoặc xử lý trực tiếp DB ở NodeJS nếu muốn)
  const url = `${server}${database}/table/${ma_ban}/status?token=${token}`;
  const bodyStr = `status=${status}`;
  
  // Gửi request cập nhật status sang backend
  request.put({
    url: url,
    body: bodyStr,
    headers: { 'content-type': 'application/x-www-form-urlencoded' }
  }, function(error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });

    try {
      // Parse response từ backend
      const result = JSON.parse(body);

      // Phát socket realtime cho FE (nếu có)
      const io = req.app.get('io');
      if (io) {
        io.emit('table_status_update', { ma_ban, status });
      }

      // Trả kết quả cho FE
      return res.send(result);
    } catch (e) {
      return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message, raw: body });
    }
  });
});



// Lấy chi tiết hóa đơn bán lẻ theo stt_rec
router.route('/:database/voucher/dpbl/:stt_rec').get(function (req, res) {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.headers['access-token'] || req.query.token || "";

  if (!token) {
    return res.status(401).send({ message: "Thiếu token" });
  }

  // Xây dựng URL gọi đến WCF
  let url = `${server}${database}/voucher/dpbl/${encodeURIComponent(stt_rec)}?token=${token}`;

  // Thêm các tham số truy vấn khác nếu có (ngoại trừ token)
  for (let q in req.query) {
    if (q !== "token") {
      let v_q = req.query[q];
      if (v_q === true || v_q === "true") v_q = "1";
      if (v_q === false || v_q === "false") v_q = "0";
      url += `&${q}=${encodeURIComponent(v_q)}`;
    }
  }

  // Gửi request đến WCF
  request(url, function (error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });

    if (body.includes("ERROR")) {
      return res.status(400).send({ message: body });
    }

    try {
      const json = JSON.parse(body);
      return res.send(json);
    } catch (e) {
      return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message });
    }
  });
});

// Update so luong DPBL
// Cập nhật số lượng hoặc xóa dòng dpbl (POST)
router.route('/:database/voucher/dpbl/:stt_rec').post(function (req, res) {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.headers['access-token'] || req.query.token || "";
  if (!token) return res.status(401).send({ message: "Thiếu token" });

  let url = `${server}${database}/voucher/dpbl/${encodeURIComponent(stt_rec)}?token=${token}`;
  // Forward toàn bộ query params khác nếu có
  for (let q in req.query) {
    if (q !== "token") {
      let v_q = req.query[q];
      if (v_q === true || v_q === "true") v_q = "1";
      if (v_q === false || v_q === "false") v_q = "0";
      url += `&${q}=${encodeURIComponent(v_q)}`;
    }
  }
  // Forward body (form-urlencoded)
  request.post({
    url: url,
    body: req.body,
    headers: { 'content-type': 'application/x-www-form-urlencoded' }
  }, function (error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });
    if (body.includes("ERROR")) return res.status(400).send({ message: body });
   try {
  // Loại bỏ BOM nếu có
  if (body.charCodeAt(0) === 0xFEFF) {
    body = body.slice(1);
  }
  const json = JSON.parse(body);
  return res.send(json);

const io = req.app.get('io');
if (io) {
  io.emit('order_update', { stt_rec, ma_ban: req.body.ma_ban });
}



} catch (e) {
  return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message });
}
  });
});


//Payvoucher
// Thanh toán phiếu bán lẻ (PayVoucher)
router.put("/:database/voucher/mpbl/:stt_rec/pay", (req, res) => {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.headers["access-token"] || req.query.token || "";

  // Gọi đến WCF API
  const url = `http://localhost:1985/${database}/voucher/mpbl/${stt_rec}/pay?token=${token}`;
  console.log("💳 Gọi PayVoucher WCF:", url);

  request.put(
    {
      url: url,
      headers: { "Content-Type": "application/json" },
      body: ""
    },
    (error, response, body) => {
      if (error) return res.status(500).send({ message: error.message });
      if (body.includes("ERROR")) {
        return res.status(400).send({ message: body });
      }
      try {
        const data = JSON.parse(body);
        res.send(data);

        // Lấy ma_ban chuẩn xác từ data trả về
        let ma_ban = req.body.ma_ban;
        if (!ma_ban && Array.isArray(data) && data[0] && data[0].ma_ban) {
          ma_ban = data[0].ma_ban;
        }
        const io = req.app.get('io');
        if (io && ma_ban) {
          io.emit('order_paid', { stt_rec, ma_ban });
          io.emit('order_update', { stt_rec, ma_ban });
        }
      } catch (e) {
        if (!res.headersSent) {
          res.status(500).send({ message: "Lỗi phân tích JSON", raw: body });
        }
      }
    }
  );
});


//tra ban
// Trả bàn - xóa phiếu mpbl + dpbl và reset trạng thái bàn
// Trả bàn/hủy phiếu bán lẻ (DeleteVoucher)
router.delete("/:database/voucher/mpbl/:stt_rec", (req, res) => {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.query.token || req.headers['access-token'] || req.body.token || "";

  if (!stt_rec) {
    return res.status(400).send({ message: "Thiếu stt_rec!" });
  }
  const url = `http://localhost:1985/${database}/voucher/mpbl/${stt_rec}?token=${token}`;
  // Gọi tới backend bằng DELETE (nếu VB.NET dùng WebInvoke với Method="DELETE")
 require("request").delete(url, (error, response, body) => {
    if (error) return res.status(500).send({ message: error.message });
    if (body && body.includes("ERROR")) {
      return res.status(400).send({ message: body });
    }
    try {
      const data = JSON.parse(body);
      res.send(data);

      let ma_ban = req.body.ma_ban;
      if (!ma_ban && Array.isArray(data) && data[0] && data[0].ma_ban) {
        ma_ban = data[0].ma_ban;
      }
      const io = req.app.get('io');
      if (io && ma_ban) {
        io.emit('table_returned', { stt_rec, ma_ban });
      }
    } catch (e) {
      if (!res.headersSent) {
        res.status(500).send({ message: "Lỗi phân tích JSON", raw: body });
      }
    }
  });
});

// GET thông tin phiếu mpbl theo stt_rec
router.get('/:database/voucher/mpbl/:stt_rec', function(req, res) {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.query.token || req.headers['access-token'] || "";
  const url = `${server}${database}/voucher/mpbl/${stt_rec}?token=${token}`;
  request.get({ url }, function(error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });
    try {
      return res.send(JSON.parse(body));
    } catch (e) {
      return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message, raw: body });
    }
  });
});

//Lay DMVT join DPBL
router.get('/:database/voucher/dpbl/:stt_rec/detail', function(req, res) {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;
  const token = req.query.token || req.headers['access-token'] || "";
  const url = `${server}${database}/voucher/dpbl/${stt_rec}/detail?token=${token}`;
  request.get({ url }, function(error, response, body) {
    if (error) return res.status(400).send({ message: error.message || error });
    try {
      return res.send(JSON.parse(body));
    } catch (e) {
      return res.status(500).send({ message: "Lỗi parse JSON từ WCF", detail: e.message, raw: body });
    }
  });
});


//chuyen ban
router.post("/:database/voucher/mpbl/:stt_rec/switch-table", (req, res) => {
  const database = req.params.database;
  const stt_rec = req.params.stt_rec;

  // Lấy token từ query hoặc headers
  const token = req.headers["access-token"] || req.query.token || req.body.token || "";
  // Lấy to_table từ body HOẶC từ query (ưu tiên body)
  const to_table = req.body.to_table || req.query.to_table;

  if (!to_table) {
    return res.status(400).send({ message: "Thiếu tham số 'to_table'" });
  }

  const url = `http://localhost:1985/${database}/voucher/mpbl/${stt_rec}/switch-table?token=${token}&to_table=${to_table}`;
  console.log("🔁 Đổi bàn WCF:", url);

   request.post(
    {
      url: url,
      headers: { "Content-Type": "application/json" },
      body: ""
    },
    (error, response, body) => {
      if (error) return res.status(500).send({ message: error.message });
      if (body.includes("ERROR")) {
        return res.status(400).send({ message: body });
      }
      try {
        const data = JSON.parse(body);
        res.send(data);

        // Lấy bàn cũ và bàn mới chính xác
        let to_table = req.body.to_table || req.query.to_table;
        let from_table = req.body.from_table || req.query.from_table;
        const io = req.app.get('io');
        if (io && to_table) {
          io.emit('order_update', { stt_rec, ma_ban: to_table });
        }
        if (io && from_table) {
          io.emit('order_update', { stt_rec, ma_ban: from_table });
        }
      } catch (e) {
        if (!res.headersSent) {
          res.status(500).send({ message: "Lỗi phân tích JSON", raw: body });
        }
      }
    }
  );
});


	//////////////////////Test Voucher insert////////////
	router.route('/:database/voucher/:voucherid').post(function (req, res, next) {
		const database = req.params.database;
		const voucherid = req.params.voucherid;
		const body = req.body;
		const token = req.headers['access-token'] || req.query.access_token;
	
		console.log('Request Query Body: ', body);
		console.log('Request Query VoucherID: ', voucherid);
	
		if (!token) {
			return res.status(400).send({ message: 'Token is required' });
		}
	
		let url = `${server}${database}/voucher/${voucherid}?token=${token}`;
		console.log('Request URL:', url);
	
		const options = {
			method: 'POST',
			url: url,
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			form: body
		};
	
		request(options, function (error, response) {
			if (error) {
				return res.status(400).send({ message: error.message || error });
			}
	
			let responseBody = response.body;
			console.log("Response Body:", responseBody);
	
			// Kiểm tra xem phản hồi có phải là HTML không
			if (response.headers['content-type'] && response.headers['content-type'].includes('text/html')) {
				console.error('Server returned an HTML error page:', responseBody);
				return res.status(500).send({ message: 'The server encountered an error processing the request. See server logs for more details.', detail: responseBody });
			}
	
			// Xử lý phản hồi XML
			parseString(responseBody, { explicitArray: false }, (err, result) => {
				if (err) {
					console.error('Lỗi phân tích cú pháp XML:', err);
					return res.status(500).send({ message: 'Lỗi phân tích cú pháp XML.', detail: err.message });
				}
	
				if (!result || !result.string || !result.string._) {
					console.error('Không có dữ liệu phản hồi XML:', result);
					return res.status(500).send({ message: 'Không có dữ liệu phản hồi XML.', detail: result });
				}
	
				try {
					const jsonResponse = JSON.parse(result.string._);
					console.log('Parsed Response Body:', jsonResponse);
					res.send(jsonResponse);
				} catch (e) {
					console.error('Lỗi phân tích cú pháp phản hồi:', e);
					return res.status(500).send({ message: 'Lỗi phản hồi từ máy chủ.', detail: e.message });
				}
			});
		});
	});

	//////////////////////Edit Item//////////////
	router.route('/:database/list/:id/:key/:value').put(function (req, res, next) {
		const database = req.params.database;
		const id = req.params.id;
		const key = req.params.key;
		const value = req.params.value;
		const body = req.body;
		const token = req.headers['access-token'] || req.query.access_token;
	
		let url = server + database + "/list/" + id + "/" + key + "/" + value + "?token=" + token;


		var options = {
			'method': 'PUT',
			'url': url,
			'headers': {
			  'Content-Type': 'application/x-www-form-urlencoded'
			},
			form: body
		  };
		  request(options, function (error, response) {
			if (error)  return res.status(400).send({ message: error.message || error });
			let body = response.body;
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
		  });
		
	
	});


	/////////////////////
		//////////////////////Add Item///////////////{database}/list/{id}?token={token}", Method:="POST")>
	router.route('/:database/list/:id/').post(function (req, res, next) {
		const database = req.params.database;
		const id = req.params.id;
		
			const body = req.body;
		const token = req.headers['access-token'] || req.query.access_token;
	
		let url = server + database + "/list/" + id +  "?token=" + token;


		var options = {
			'method': 'POST',
			'url': url,
			'headers': {
			  'Content-Type': 'application/x-www-form-urlencoded'
			},
			form: body
		  };
		  request(options, function (error, response) {
			if (error)  return res.status(400).send({ message: error.message || error });
			let body = response.body;
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
		  });
		
	
	});



	//////////////////////Edit Voucher//////////////"/{database}/voucher/{id}/update/{stt_rec}?token={token}")>
	
	router.route('/:database/voucher/:id/:stt_rec').put(function (req, res, next) {
		const database = req.params.database;
		const id = req.params.id;
		const stt_rec = req.params.stt_rec;
	
		const body = req.body;
		const token = req.headers['access-token'] || req.query.access_token;
	
		if (!token) {
			return res.status(400).send({ message: "ERROR: Chức năng này yêu cầu biến token" });
		}
	
		let url = server + "/" + database + "/voucher/" + id + "/" + stt_rec + "?token=" + token;
		console.log('Constructed URL:', url);
		const options = {
			method: 'PUT',
			url: url,
			headers: {
				'Content-Type': 'application/json'
			},
			json: body // Sử dụng `json` để gửi JSON payload
		};
	
		request(options, function (error, response, body) {
			if (error) {
				return res.status(400).send({ message: error.message || error });
			}

			console.log('Response status code:', response.statusCode);
			console.log('Response body:', body);
	
			if (response.statusCode !== 200) {
				return res.status(response.statusCode).send({ message: body });
			}
	
			res.send(body);
		});
	});
	///////////////////////////////////////


	///////////////////Delete Data////////////
	
	router.route('/:database/list/:id/:key/:value').delete(function (req, res, next) {
		const database = req.params.database;
		const id = req.params.id;
		const key = req.params.key;
		const value = req.params.value;
		const body = req.body;
		const token = req.headers['access-token'] || req.query.access_token;
	
		let url = server + database + "/list/" + id + "/" + key + "/" + value + "?token=" + token;


		var options = {
			'method': 'DELETE',
			'url': url,
			'headers': {
			  'Content-Type': 'application/x-www-form-urlencoded'
			},
			form: body
		  };
		  request(options, function (error, response) {
			if (error)  return res.status(400).send({ message: error.message || error });
			let body = response.body;
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
		  });
		
	
	});
	

	///////////////////////////////exec sql//////////
	router.route('/:database/getdata').get(async function (req, res, next) {
  const database = req.params.database;
  const query = req.query.body;
  const token = req.headers['access-token'] || req.query.access_token;
  
  console.log('Request Query 0 ********:', query);

  // Kiểm tra xem các tham số có hợp lệ không
  if (!database || !query || !token) {
    return res.status(400).send({ message: 'Missing required parameters' });
  }

  try {
    // Xây dựng URL với query string
    const queryString = querystring.stringify({ store: query });
    const url = `${server}${database}/getdata?token=${token}&${queryString}`;

    console.log('Request URL:', url);

    // Gửi yêu cầu GET với axios
    const options = {
      method: 'GET',
      url: url,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    };

    const response = await axios(options);

    let responseBody = response.data;
    console.log('Response Body:', responseBody);

    // Phân tích cú pháp XML để chuyển sang JavaScript object
    xml2js.parseString(responseBody, { explicitArray: false }, (err, result) => {
      if (err) {
        console.error('❌ Lỗi phân tích cú pháp XML:', err);
        return res.status(500).send({ message: 'Lỗi phân tích cú pháp XML.' });
      }

      console.log('✅ Kết quả sau khi parse XML:', JSON.stringify(result, null, 2));

      // Kiểm tra nếu dữ liệu có thể chuyển thành JSON hợp lệ từ XML
      const stringField = result?.string?._;

      if (!stringField) {
        return res.status(500).send({ message: 'Không tìm thấy nội dung trong thẻ <string>' });
      }

      // Kiểm tra xem dữ liệu có phải là JSON hợp lệ không
      try {
        // Nếu dữ liệu không phải JSON, sẽ không cố parse
        const maybeJSON = stringField.trim();

        if (!maybeJSON.startsWith('{') && !maybeJSON.startsWith('[')) {
          return res.status(500).send({ message: 'Nội dung không phải JSON.' });
        }

        const jsonResponse = JSON.parse(maybeJSON);
        res.send(jsonResponse); // Gửi phản hồi JSON cho client
      } catch (e) {
        console.error('❌ Lỗi phân tích JSON từ XML:', e);
        return res.status(500).send({ message: 'Lỗi phân tích JSON từ XML.', detail: e.message });
      }
    });
  } catch (error) {
    console.error('❌ Lỗi khi gửi yêu cầu:', error);
    return res.status(400).send({ message: error.message || error });
  }
});

	  //////////////////Tạo voucher//////
	  router.post('/create_invoice', async (req, res) => {
		const { ma_ct, ma_ban, status, access_token } = req.body;
	  
		try {
		  // Kết nối đến cơ sở dữ liệu
		  const pool = await sql.connect('mssql://username:password@localhost/database');
	  
		  // Thực hiện câu lệnh SQL để tạo phiếu bán lẻ
		  await pool.request()
			.input('ma_ct', sql.NVarChar, ma_ct)
			.input('ma_ban', sql.NVarChar, ma_ban)
			.input('status', sql.Int, status)
			.query('INSERT INTO Mpbl (ma_ct, ma_ban, status) VALUES (@ma_ct, @ma_ban, @status)');
	  
		  res.json({ success: true });
		} catch (error) {
		  console.error('Error creating invoice:', error);
		  res.status(500).json({ success: false, message: 'Error creating invoice' });
		}
	  });

	  //////////////////////

///////////////////////////////////////////////
	//ent report
	router.route('/:database/report/:id_rpt/:stt/info').get(function (req, res, next) {
		const database = req.params.database;
		const id_rpt = req.params.id_rpt;
		const stt = req.params.stt;
		const token = req.headers['access-token'] || req.query.access_token;
		let url = server + database + "/report/" + id_rpt + "/" + stt + "/info?token=" + token;
		request(url, function (error, response, body) {
			if (error) {
				console.error(error);
				console.error(url);
				return res.status(400).send({ message: error.message || error });
			}
			if (body.indexOf("ERROR") >= 0) {
				console.error(body);
				console.error(url);
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
			} catch (e) {
				console.error(body);
				console.error(url);
				return res.status(400).send({ message: e.message || e });
			}
			return res.send(body);
		});
	});
	router.route('/:database/report/:id_rpt/:stt').get(function (req, res, next) {
		const database = req.params.database;
		const id_rpt = req.params.id_rpt;
		const stt = req.params.stt;
		const token = req.headers['access-token'] || req.query.access_token;
		let url = server + database + "/report/" + id_rpt + "/" + stt + "?token=" + token;
		let v_q;
		for (let q in req.query) {
			if (q !== "access_token") {
				v_q = req.query[q];
				if (v_q == true || v_q == "true") {
					v_q = "1"
				}
				if (v_q == false || v_q == "false") {
					v_q == "0"
				}
				url = url + "&" + q + "=" + encodeURI(v_q);
			}
		}
		request(url, function (error, response, body) {
			if (error) {
				console.error(error);
				console.error(url);
				return res.status(400).send({ message: error.message || error });
			}
			if (body.indexOf("ERROR") >= 0) {
				console.error(body);
				console.error(url);
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
			} catch (e) {
				console.error(body);
				console.error(url);
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
		});
	});

/////////////////////////////////store proc////////////////

router.route('/:database/getdata').get(async function (req, res, next) {
	const database = req.params.database;
	const query = req.query.body;
	const token = req.headers['access-token'] || req.query.access_token;
	console.log('Request Query1 ********:', query);
  
	if (!database || !query || !token) {
	  return res.status(400).send({ message: 'Missing required parameters' });
	}
  
	try {
	  // Xây dựng URL với query string
	  const queryString = querystring.stringify({ store: query });
	  const url = `${server}${database}/getdata?token=${token}&${queryString}`;
  
	  console.log('Request URL:', url);
  
	  const options = {
		method: 'GET',
		url: url,
		headers: {
		  'Content-Type': 'application/x-www-form-urlencoded'
		}
	  };
  
	  // Gửi yêu cầu GET bằng axios
	  const response = await axios(options);
  
	  let responseBody = response.data;
	  console.log('Response Body: ', responseBody);
  
	  try {
		responseBody = JSON.parse(responseBody);
	  } catch (e) {
		//console.error('Lỗi phân tích cú pháp phản hồi:', e);
		return res.status(500).send({ message: 'Lỗi phản hồi từ máy chủ.' });
	  }
  
	  res.send(responseBody);
	  console.log('Phản hồi từ máy chủ:', responseBody);
	} catch (error) {
	  console.error('Request error:', error);
	  res.status(400).send({ message: error.message || error });
	}
  });
////////////////////////////////////////////////


	//ent voucher
	router.route('/:database/voucher/:voucherid/info').get(function (req, res, next) {
		const database = req.params.database;
		const voucherid = req.params.voucherid;
		const token = req.headers['access-token'] || req.query.access_token;
		let url = server + database + "/voucher/" + voucherid + "/info?token=" + token;
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			return res.send(body);
		});
	});

	router.route('/:database/voucher/:voucherid').get(function (req, res, next) {
		const database = req.params.database;
		const voucherid = req.params.voucherid;
		const token = req.headers['access-token'] || req.query.access_token;
		let url = server + database + "/voucher/" + voucherid + "?token=" + token + "&ma_ct=" + voucherid;
		let v_q;
		for (var q in req.query) {
			if (q !== "access_token") {
				v_q = req.query[q];
				if (v_q == true || v_q == "true") {
					v_q = "1"
				}
				if (v_q == false || v_q == "false") {
					v_q == "0"
				}
				url = url + "&" + q + "=" + encodeURI(v_q);
			}
		}
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
		});
	});



//////////////////////////////////////////////////////////


	router.route('/:database/voucher/:voucherid/update/:stt_rec').get(function (req, res, next) {
		const database = req.params.database;
		const voucherid = req.params.voucherid;
		const token = req.headers['access-token'] || req.query.access_token;
		const stt_rec = req.params.stt_rec;
		let url = server + database + "/voucher/" + voucherid + "/update/" + stt_rec + "?token=" + token;
		let v_q;
		for (let q in req.query) {
			if (q !== "access_token") {
				v_q = req.query[q];
				url = url + "&" + q + "=" + encodeURI(v_q);
			}
		}
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
			res.send(body);
		});
	});
	router.route('/:database/optgroupby').get(function (req, res, next) {
		const database = req.params.database;
		const token = req.headers['access-token'] || req.query.access_token;
		const where = req.query.where || "1=0";
		const store = "select codeid,headerV as txt,headerE as txt2 from optgroupby where " + where;
		let url = server + database + "/getdata?token=" + token + "&store=" + store;
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
				body = JSON.parse(body);
				return res.send(body.Table);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
		});
	});

////////////////////////////////////////////Insert PBL///////////
router.route('/:database/voucher/:voucherid').post(function (req, res, next) {
	const database = req.params.database;
	const voucherid = req.params.voucherid;
	const body = req.body;

	const token = req.headers['access-token'] || req.query.access_token;

	let url = server + database + "/voucher/" + voucherid + "?token=" + token;

	var options = {
		'method': 'POST',
		'url': url,
		'headers': {
		  'Content-Type': 'application/x-www-form-urlencoded'
		},
		form: body
	  };
	  request(options, function (error, response) {
		if (error)  return res.status(400).send({ message: error.message || error });
		let body = response.body;
		try {
			body = JSON.parse(body);
		} catch (e) {
			return res.status(400).send({ message: e.message || e });
		}
		res.send(body);
		console.log(body);
	  });
	

});

///////////////////////////////////////




	router.route('/:database/dmitemofcbb/:form/:name').get(function (req, res, next) {
		const database = req.params.database;
		const token = req.headers['access-token'] || req.query.access_token;
		const form = req.params.form;
		const name = req.params.name;
		const store = `select * from dmitemofcbb where form='${form}' and name='${name}'`;
		let url = server + database + "/getdata?token=" + token + "&store=" + store;
		request(url, function (error, response, body) {
			if (error) return res.status(400).send({ message: error.message || error });
			if (body.indexOf("ERROR") >= 0) {
				return res.status(400).send({ message: body });
			}
			try {
				body = JSON.parse(body);
				body = JSON.parse(body);
				return res.send(body.Table);
			} catch (e) {
				return res.status(400).send({ message: e.message || e });
			}
		});
	});

	//////////////////////////API lay DS Ban///
	// Middleware để xử lý JSON body
app.use(express.json());

// API để lấy dữ liệu các bàn
app.post('/:database/tables', async (req, res) => {
  const { query } = req.body;
  try {
    if (!query) {
      return res.status(400).send('Query is required');
    }
    const result = await sql.query(query);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).send(err.message);
  }
});
	///////////////////////////////

// //get data
	// router.route('/:database/gridinfo/:gridid').get(function (req, res, next) {
	// 	const database = req.params.database;
	// 	const gridid = req.params.gridid;
	// 	const token = req.headers['access-token'] || req.query.access_token;
	// 	let url = server + database + "/gridinfo/" + gridid + "?token=" + token;
	// 	request(url, function (error, response, body) {
	// 		if (error) return res.status(400).send({ message: error.message || error });
	// 		if (body.indexOf("ERROR") >= 0) {
	// 			return res.status(400).send({ message: body });
	// 		}
	// 		try {
	// 			body = JSON.parse(body);
	// 		} catch (e) {
	// 			return res.status(400).send({ message: e.message || e });
	// 		}
	// 		return res.send(body);
	// 	});
	// });

	// router.route('/:database/list/:id_list/info').get(function (req, res, next) {
	// 	const database = req.params.database;
	// 	const id_list = req.params.id_list;
	// 	const token = req.headers['access-token'] || req.query.access_token;
	// 	let url = server + database + "/list/" + id_list + "/info?token=" + token;
	// 	request(url, function (error, response, body) {
	// 		if (error) return res.status(400).send({ message: error.message || error });
	// 		if (body.indexOf("ERROR") >= 0) {

	// 			return res.status(400).send({ message: body });
	// 		}
	// 		try {
	// 			body = JSON.parse(body);
	// 		} catch (e) {
	// 			return res.status(400).send({ message: e.message || e });
	// 		}
	// 		return res.send(body);
	// 	});
	// });
	//ent list

///////////////



	router.route('/:database/send-notification/:user/:event').get(async (req, res, next) => {
		const database = req.params.database;
		const user = req.params.user;
		const event = req.params.event;
		const token = req.headers['access-token'] || req.query.access_token;
		const endpoint = req.query.endpoint;
		const _data = Object.assign({}, req.query);
		if (_data.title) _data.title = unescape(_data.title);
		delete _data.access_token;
		try {
			await emitEvent(user, event, _data, true, database, token, endpoint);
			res.send("OK");
		} catch (e) {
			return res.status(400).send({ message: e.message || e });
		}

	});
};
