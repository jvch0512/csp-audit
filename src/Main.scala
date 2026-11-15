package csp

import java.io.File

object Main {
  def usage(): Int = {
    System.err.println("usage: csp-audit PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.")
    2
  }

  def walk(f: File): List[File] =
    if (f.isDirectory) Option(f.listFiles).map(_.toList).getOrElse(Nil).flatMap(walk) else List(f)

  def run(args: Array[String]): Int = {
    var path: Option[String] = None
    var tsv = false
    var failOn: Option[String] = None
    var i = 0
    while (i < args.length) {
      val a = args(i)
      if (a == "--tsv") tsv = true
      else if (a == "--fail-on") {
        i += 1
        if (i >= args.length || !Set("medium", "high", "critical")(args(i))) return usage()
        failOn = Some(args(i))
      } else if (a.startsWith("-")) return usage()
      else if (path.isDefined) return usage()
      else path = Some(a)
      i += 1
    }
    if (path.isEmpty) return usage()
    val root = new File(path.get)
    if (!root.exists) { System.err.println("error: no such file or directory: " + path.get); return 2 }
    val files: List[(String, File)] =
      if (root.isDirectory) {
        val base = root.getAbsoluteFile.toPath
        walk(root).filter(f => f.getName.endsWith(".headers") || f.getName.endsWith(".txt"))
          .map(f => (base.relativize(f.getAbsoluteFile.toPath).toString.replace('\\', '/'), f)).sortBy(_._1)
      } else List((root.getName, root))
    val all = files.flatMap { case (label, f) =>
      if (f.length > 4000000L) Nil
      else Audit.audit(new String(java.nio.file.Files.readAllBytes(f.toPath), "UTF-8"), label)
    }
    val sorted = Audit.sort(all)
    val head = files.size + " files, " + sorted.size + " findings"
    println(if (tsv) "# " + head else head)
    sorted.foreach { f =>
      if (tsv) println(List(f.sev, f.rule, f.where, f.msg).mkString("\t"))
      else { println("%-8s %s %s".format(f.sev.toUpperCase, f.rule, f.where)); println("         " + f.msg) }
    }
    failOn match {
      case Some(level) if sorted.exists(f => Audit.Rank(f.sev) <= Audit.Rank(level)) => 1
      case _ => 0
    }
  }

  def main(args: Array[String]): Unit = sys.exit(run(args))
}
