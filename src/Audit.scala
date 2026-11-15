package csp

case class Finding(sev: String, rule: String, where: String, msg: String)
case class Header(name: String, value: String, line: Int)
case class Response(start: Int, status: String, headers: List[Header]) {
  def all(n: String): List[Header] = headers.filter(_.name.equalsIgnoreCase(n))
  def first(n: String): Option[Header] = all(n).headOption
}

object Audit {
  val Rank = Map("critical" -> 0, "high" -> 1, "medium" -> 2, "low" -> 3, "info" -> 4)

  /** Splits text into responses. A response starts at an HTTP/ status line or at the first header line. */
  def parse(text: String): List[Response] = {
    val lines = text.split("\r\n|\n|\r", -1).toList
    var res = List.empty[Response]
    var cur: Option[(Int, String, List[Header])] = None
    def close(): Unit = cur.foreach { case (s, st, hs) => if (hs.nonEmpty) res = Response(s, st, hs.reverse) :: res }
    lines.zipWithIndex.foreach { case (raw, i) =>
      val line = raw.trim
      val n = i + 1
      if (line.isEmpty) { close(); cur = None }
      else if (line.toUpperCase.startsWith("HTTP/")) { close(); cur = Some((n, line.take(60), Nil)) }
      else {
        val c = line.indexOf(':')
        if (c > 0 && !line.substring(0, c).exists(ch => ch == ' ' || ch == '\t')) {
          val h = Header(line.substring(0, c).trim, line.substring(c + 1).trim, n)
          cur = cur match {
            case Some((s, st, hs)) => Some((s, st, h :: hs))
            case None => Some((n, "", List(h)))
          }
        }
      }
    }
    close()
    res.reverse
  }

  def directives(csp: String): Map[String, List[String]] =
    csp.split(";").toList.map(_.trim).filter(_.nonEmpty).map { d =>
      val parts = d.split("\\s+").toList
      parts.head.toLowerCase -> parts.tail.map(_.toLowerCase)
    }.foldLeft(Map.empty[String, List[String]]) { case (m, (k, v)) => if (m.contains(k)) m else m + (k -> v) }

  def audit(text: String, label: String): List[Finding] = {
    val rs = parse(text)
    if (rs.isEmpty) return List(Finding("info", "HDR000", label + ":1", "no HTTP header lines found"))
    rs.flatMap { r =>
      def at(h: Header) = label + ":" + h.line
      val top = label + ":" + r.start
      val out = scala.collection.mutable.ListBuffer.empty[Finding]
      val csp = r.first("Content-Security-Policy")
      val ro = r.first("Content-Security-Policy-Report-Only")
      csp match {
        case None =>
          if (ro.isDefined) out += Finding("medium", "HDR001", at(ro.get), "CSP is report-only: nothing is blocked")
          else out += Finding("high", "HDR001", top, "no Content-Security-Policy header")
        case Some(h) =>
          val d = directives(h.value)
          val script = d.get("script-src").orElse(d.get("default-src"))
          script match {
            case None => out += Finding("high", "HDR002", at(h), "CSP has neither script-src nor default-src: scripts are not restricted")
            case Some(src) =>
              val bad = src.filter(s => s == "'unsafe-inline'" || s == "'unsafe-eval'" || s == "*" || s == "data:" || s == "https:" || s == "http:")
              val nonceOrHash = src.exists(s => s.startsWith("'nonce-") || s.startsWith("'sha") || s == "'strict-dynamic'")
              val real = if (nonceOrHash) bad.filterNot(_ == "'unsafe-inline'").filterNot(_ == "https:").filterNot(_ == "http:") else bad
              if (real.nonEmpty) out += Finding("high", "HDR002", at(h), "script sources allow " + real.distinct.mkString(", "))
          }
          if (!d.contains("frame-ancestors") && r.first("X-Frame-Options").isEmpty)
            out += Finding("medium", "HDR003", at(h), "no frame-ancestors in CSP and no X-Frame-Options: the page can be framed")
      }
      if (csp.isEmpty && r.first("X-Frame-Options").isEmpty)
        out += Finding("medium", "HDR003", top, "no frame-ancestors and no X-Frame-Options: the page can be framed")
      r.first("Strict-Transport-Security") match {
        case None => out += Finding("medium", "HDR004", top, "no Strict-Transport-Security header")
        case Some(h) =>
          val m = """(?i)max-age\s*=\s*"?(\d+)""".r.findFirstMatchIn(h.value).map(g => if (g.group(1).length > 15) Long.MaxValue else g.group(1).toLong)
          if (m.isEmpty || m.get < 15552000L) out += Finding("medium", "HDR004", at(h), "HSTS max-age is " + m.map(_.toString).getOrElse("missing") + ": use at least 15552000 (6 months)")
      }
      if (!r.first("X-Content-Type-Options").exists(_.value.toLowerCase.contains("nosniff")))
        out += Finding("low", "HDR005", top, "no X-Content-Type-Options: nosniff")
      if (r.first("Referrer-Policy").isEmpty) out += Finding("low", "HDR006", top, "no Referrer-Policy header")
      r.all("Set-Cookie").foreach { h =>
        val attrs = h.value.split(";").toList.map(_.trim.toLowerCase)
        val name = h.value.takeWhile(_ != '=')
        val missing = List("secure", "httponly").filterNot(a => attrs.contains(a))
        if (missing.nonEmpty) out += Finding("medium", "HDR007", at(h), "cookie " + name + " lacks " + missing.mkString(" and "))
        else if (!attrs.exists(_.startsWith("samesite"))) out += Finding("low", "HDR007", at(h), "cookie " + name + " has no SameSite attribute")
      }
      List("Server", "X-Powered-By", "X-AspNet-Version").foreach { n =>
        r.first(n).foreach { h =>
          if (h.value.exists(_.isDigit)) out += Finding("low", "HDR008", at(h), n + " discloses a version: " + h.value.take(40))
        }
      }
      r.first("Access-Control-Allow-Origin").foreach { o =>
        val creds = r.first("Access-Control-Allow-Credentials").exists(_.value.trim.equalsIgnoreCase("true"))
        if (creds && (o.value.trim == "*" || o.value.trim.equalsIgnoreCase("null")))
          out += Finding("high", "HDR009", at(o), "Access-Control-Allow-Origin " + o.value.trim + " with credentials allowed")
      }
      out.toList
    }
  }

  def sort(f: List[Finding]): List[Finding] = f.sortBy { x =>
    val i = x.where.lastIndexOf(':')
    (Rank(x.sev), x.where.substring(0, i), x.where.substring(i + 1).toInt, x.rule)
  }
}
