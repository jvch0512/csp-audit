package csp

import scala.sys.process._

object Tests {
  var passed = 0
  var failed = 0
  def check(ok: Boolean, what: String): Unit = if (ok) passed += 1 else { failed += 1; println("FAIL: " + what) }

  val good = "HTTP/2 200\nStrict-Transport-Security: max-age=31536000\nContent-Security-Policy: default-src 'none'; script-src 'self'; frame-ancestors 'none'\nX-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer\n"
  def rules(t: String): List[String] = Audit.audit(t, "t").map(_.rule)
  def has(t: String, r: String): Boolean = rules(t).contains(r)
  def without(h: String): String = good.split("\n").filterNot(_.toLowerCase.startsWith(h.toLowerCase + ":")).mkString("\n") + "\n"
  def withLine(l: String): String = good + l + "\n"
  def cli(args: String*): (Int, String) = {
    val out = new StringBuilder
    val code = (Seq("scala", "-cp", "build", "csp.Main") ++ args).!(ProcessLogger(l => out.append(l).append("\n"), _ => ()))
    (code, out.toString)
  }

  def main(args: Array[String]): Unit = {
    // parser
    val rs = Audit.parse("HTTP/1.1 200 OK\nA: 1\nB: two words\n\nHTTP/1.1 404\nC: 3\n")
    check(rs.size == 2, "two responses")
    check(rs(0).first("b").exists(_.value == "two words"), "header lookup is case-insensitive")
    check(rs(1).headers.head.line == 6, "line numbers")
    check(Audit.parse("A: 1\nB: 2\n").size == 1, "response without a status line")
    check(Audit.parse("").isEmpty && Audit.parse("\n\n").isEmpty, "empty input")
    check(Audit.parse("not a header line\nrandom words here\n").isEmpty, "non-header text is ignored")
    check(Audit.parse("A: 1\r\nB: 2\r\n").head.headers.size == 2, "CRLF")
    check(Audit.parse("HTTP/1.1 200\nSet-Cookie: a=b\nSet-Cookie: c=d\n").head.all("set-cookie").size == 2, "repeated headers")
    val d = Audit.directives("default-src 'self'; Script-Src 'self' https://a.test; script-src evil.test")
    check(d("script-src") == List("'self'", "https://a.test"), "directives are lower-cased, first occurrence wins")

    // clean
    check(rules(good).isEmpty, "a well configured response has no findings")
    check(rules("").contains("HDR000") && Audit.audit("", "t").head.sev == "info", "HDR000")

    // HDR001
    check(has(without("Content-Security-Policy"), "HDR001"), "no CSP")
    check(Audit.audit(without("Content-Security-Policy"), "t").exists(f => f.rule == "HDR001" && f.sev == "high"), "no CSP is high")
    val ro = without("Content-Security-Policy") + "Content-Security-Policy-Report-Only: default-src 'self'\n"
    check(Audit.audit(ro, "t").exists(f => f.rule == "HDR001" && f.sev == "medium"), "report-only is medium")
    // HDR002
    for (v <- List("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "https:"))
      check(has(good.replace("script-src 'self'", "script-src 'self' " + v), "HDR002"), "script-src with " + v)
    check(has(good.replace("script-src 'self'; ", "").replace("default-src 'none'", "default-src 'self' 'unsafe-inline'"), "HDR002"), "falls back to default-src")
    check(has(good.replace("default-src 'none'; script-src 'self'; ", ""), "HDR002"), "no script-src and no default-src")
    check(!has(good.replace("script-src 'self'", "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic' https:"), "HDR002"), "nonce makes unsafe-inline harmless")
    check(has(good.replace("script-src 'self'", "script-src 'nonce-abc' 'unsafe-eval'"), "HDR002"), "unsafe-eval stays bad with a nonce")
    check(!has(good.replace("script-src 'self'", "script-src 'self' https://cdn.example.test"), "HDR002"), "named host is fine")
    // HDR003
    check(has(good.replace("; frame-ancestors 'none'", ""), "HDR003"), "no frame-ancestors")
    check(!has(good.replace("; frame-ancestors 'none'", "") + "X-Frame-Options: DENY\n", "HDR003"), "X-Frame-Options is enough")
    check(has(without("Content-Security-Policy"), "HDR003"), "no CSP and no XFO")
    // HDR004
    check(has(without("Strict-Transport-Security"), "HDR004"), "no HSTS")
    check(has(without("Strict-Transport-Security") + "Strict-Transport-Security: max-age=300\n", "HDR004"), "short HSTS")
    check(has(without("Strict-Transport-Security") + "Strict-Transport-Security: includeSubDomains\n", "HDR004"), "HSTS without max-age")
    check(!has(without("Strict-Transport-Security") + "Strict-Transport-Security: max-age=15552000\n", "HDR004"), "exactly six months passes")
    // HDR005, HDR006
    check(has(without("X-Content-Type-Options"), "HDR005"), "no nosniff")
    check(has(without("X-Content-Type-Options") + "X-Content-Type-Options: other\n", "HDR005"), "wrong nosniff value")
    check(has(without("Referrer-Policy"), "HDR006"), "no referrer policy")
    // HDR007
    check(has(withLine("Set-Cookie: s=1; Path=/"), "HDR007"), "cookie without flags")
    check(has(withLine("Set-Cookie: s=1; Secure"), "HDR007"), "cookie without HttpOnly")
    check(Audit.audit(withLine("Set-Cookie: s=1; Secure; HttpOnly"), "t").exists(f => f.rule == "HDR007" && f.sev == "low"), "cookie without SameSite is low")
    check(!has(withLine("Set-Cookie: s=1; secure; httponly; SameSite=Strict"), "HDR007"), "good cookie, any case")
    // HDR008
    check(has(withLine("Server: nginx/1.18.0"), "HDR008") && has(withLine("X-Powered-By: PHP/8.1"), "HDR008"), "version disclosure")
    check(!has(withLine("Server: nginx"), "HDR008"), "no version is fine")
    // HDR009
    check(has(withLine("Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"), "HDR009"), "wildcard with credentials")
    check(has(withLine("Access-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true"), "HDR009"), "null origin with credentials")
    check(!has(withLine("Access-Control-Allow-Origin: *"), "HDR009"), "wildcard without credentials")
    check(!has(withLine("Access-Control-Allow-Origin: https://a.test\nAccess-Control-Allow-Credentials: true"), "HDR009"), "named origin")

    // locations and sorting
    val f = Audit.audit("HTTP/1.1 200\nServer: x/1\n", "dir/a.headers").find(_.rule == "HDR008").get
    check(f.where == "dir/a.headers:2", "where is label:line")
    val s = Audit.sort(List(Finding("low", "B", "a:1", ""), Finding("high", "A", "b:9", ""), Finding("high", "A", "b:10", ""), Finding("high", "A", "a:2", "")))
    check(s.map(_.where) == List("a:2", "b:9", "b:10", "a:1"), "sort by severity, file, numeric line")

    // hostile input and fuzz
    var ok = true
    val hostile = List("A" * 200000, ":" * 5000, "HTTP/" * 5000, "x: " + "y" * 200000, "Content-Security-Policy: " + ";" * 50000,
      "Strict-Transport-Security: max-age=" + "9" * 5000, "Set-Cookie: =;", "\u0000: \u0000")
    hostile.foreach { h => try { Audit.audit(h, "h") } catch { case e: Throwable => ok = false; println("hostile: " + e) } }
    check(ok, "hostile inputs do not throw")
    val rnd = new scala.util.Random(42)
    val alphabet = ":;\n=\" HTTP/'*"
    var fuzzOk = true
    var i = 0
    while (i < 3000 && fuzzOk) {
      val sb = new StringBuilder(good + "Set-Cookie: a=b; Secure\nAccess-Control-Allow-Origin: *\n")
      for (_ <- 0 to rnd.nextInt(6)) {
        if (sb.isEmpty) sb.append("x")
        val pos = rnd.nextInt(sb.length)
        rnd.nextInt(3) match {
          case 0 => sb.setCharAt(pos, alphabet(rnd.nextInt(alphabet.length)))
          case 1 => sb.delete(pos, math.min(sb.length, pos + 1 + rnd.nextInt(8)))
          case _ => sb.insert(pos, alphabet(rnd.nextInt(alphabet.length)))
        }
      }
      try { Audit.audit(sb.toString, "f") } catch { case e: Throwable => fuzzOk = false; println("fuzz: " + e) }
      i += 1
    }
    check(fuzzOk, "fuzzing 3000 inputs never throws")

    // CLI
    check(cli("examples")._1 == 0, "cli exit 0")
    check(cli("examples", "--fail-on", "high")._1 == 1, "cli --fail-on high")
    check(cli("examples/docs-prod.headers", "--fail-on", "medium")._1 == 0, "clean capture passes")
    val t = cli("examples", "--tsv")._2.split("\n").filter(_.nonEmpty)
    check(t.head.startsWith("# ") && t.tail.forall(_.count(_ == '\t') == 3), "tsv format")
    check(cli("/no/such/path")._1 == 2, "missing path")
    check(cli()._1 == 2, "no args")
    check(cli("examples", "--bogus")._1 == 2, "unknown flag")
    check(cli("examples", "--fail-on", "nope")._1 == 2, "bad --fail-on")
    check(cli("examples", "examples")._1 == 2, "two paths")

    println(passed + " passed, " + failed + " failed")
    sys.exit(if (failed > 0) 1 else 0)
  }
}
