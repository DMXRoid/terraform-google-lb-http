/*
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

resource "google_compute_global_forwarding_rule" "http" {
  project    = "${var.project}"
  count      = "${var.http_forward ? 1 : 0}"
  name       = "${var.name}"
  target     = "${google_compute_target_http_proxy.default.self_link}"
  ip_address = "${google_compute_global_address.default.address}"
  port_range = "80"
  depends_on = ["google_compute_global_address.default"]
}

resource "google_compute_global_forwarding_rule" "https" {
  project    = "${var.project}"
  count      = "${var.ssl ? 1 : 0}"
  name       = "${var.name}-https"
  target     = "${google_compute_target_https_proxy.default.self_link}"
  ip_address = "${google_compute_global_address.default.address}"
  port_range = "443"
  depends_on = ["google_compute_global_address.default"]
}

resource "google_compute_global_address" "default" {
  project    = "${var.project}"
  name       = "${var.name}-address"
  ip_version = "${var.ip_version}"
}

# HTTP proxy when ssl is false
resource "google_compute_target_http_proxy" "default" {
  project = "${var.project}"
  count   = "${var.http_forward ? 1 : 0}"
  name    = "${var.name}-http-proxy"
  url_map = "${element(compact(concat(list(var.url_map), google_compute_url_map.default.*.self_link)), 0)}"
}

# HTTPS proxy  when ssl is true
resource "google_compute_target_https_proxy" "default" {
  project          = "${var.project}"
  count            = "${var.ssl ? 1 : 0}"
  name             = "${var.name}-https-proxy"
  quic_override    = "${var.quic_override}"
  url_map          = "${element(compact(concat(list(var.url_map), google_compute_url_map.default.*.self_link)), 0)}"
  ssl_certificates = ["${compact(concat(var.ssl_certificates, google_compute_ssl_certificate.default.*.self_link))}"]
}

resource "google_compute_ssl_certificate" "default" {
  project     = "${var.project}"
  count       = "${(var.ssl && !var.use_ssl_certificates) ? 1 : 0}"
  name_prefix = "${var.name}-certificate-"
  private_key = "${var.private_key}"
  certificate = "${var.certificate}"

  lifecycle = {
    create_before_destroy = true
  }
}

resource "google_compute_url_map" "default" {
  project         = "${var.project}"
  count           = "${var.create_url_map ? 1 : 0}"
  name            = "${var.name}-url-map"
  default_service = "${google_compute_backend_service.default.0.self_link}"
}

resource "google_compute_backend_service" "default" {
  project         = "${var.project}"
  count           = "${length(var.backend_parameters)}"
  name            = "${var.name}-backend-${count.index}"
  port_name       = "${lookup(var.backend_parameters[count.index], "named_port")}"
  protocol        = "${var.backend_protocol}"
  timeout_sec     = "${element(var.backend_parameters.*.timeout, count.index)}"
  backend         = ["${var.backends["${count.index}"]}"]
  health_checks   = ["${var.ssl ? google_compute_health_check.default-https[count.index].self_link : google_compute_health_check.default-http[count.index].self_link}"]
  security_policy = "${var.security_policy}"
}

resource "google_compute_health_check" "default-https" {
  name               = "${var.name}-backend-https-${count.index}"
  count              = "${var.ssl ? length(var.http_health_check) : 0}"
  timeout_sec        = "${element(var.http_health_check.*.timeout, count.index)}"
  check_interval_sec = "${element(var.http_health_check.*.check_interval, count.index)}"

  https_health_check = {
    host         = "${element(var.http_health_check.*.host, count.index)}"
    port         = "${element(var.http_health_check.*.port, count.index) }"
    proxy_header = "${element(var.http_health_check.*.proxy_header, count.index)}"
    request_path = "${element(var.http_health_check.*.request_path, count.index)}"
  }
}

resource "google_compute_health_check" "default-http" {
  name               = "${var.name}-backend-https-${count.index}"
  count              = "${var.ssl ? 0 : length(var.http_health_check)}"
  timeout_sec        = "${element(var.http_health_check.*.timeout, count.index)}"
  check_interval_sec = "${element(var.http_health_check.*.check_interval, count.index)}"

  http_health_check = {
    host         = "${element(var.http_health_check.*.host, count.index)}"
    port         = "${element(var.http_health_check.*.port, count.index) }"
    proxy_header = "${element(var.http_health_check.*.proxy_header, count.index)}"
    request_path = "${element(var.http_health_check.*.request_path, count.index)}"
  }
}

resource "google_compute_firewall" "default-hc" {
  count         = "${length(var.firewall_networks)}"
  project       = "${var.project}"
  count         = "${length(var.backend_parameters)}"
  name          = "${var.name}-hc-${count.index}"
  network       = "${element(var.firewall_networks, count.index)}"
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
  target_tags   = ["${var.target_tags}"]

  allow {
    protocol = "tcp"
    ports    = ["${element(var.http_health_check.*)}"]
  }
}
