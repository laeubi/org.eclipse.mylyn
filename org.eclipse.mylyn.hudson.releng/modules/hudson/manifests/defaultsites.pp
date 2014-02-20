define hudson::defaultsites ($base = $hudson::base,) {
  /* Defaults */

  Hudson::Hudson {
    base => "$base",
  }

  Hudson::Site {
    data => "hudson-2.1",
    base => "$base",
  }

  /* Instances */

  hudson::hudson { "3.0.1":
    type      => "hudson",
    qualifier => "eclipse",
  }

  hudson::hudson { "3.1.2":
    type      => "hudson",
    qualifier => "eclipse",
  }

  hudson::hudson { "1.509.4":
    type      => "jenkins",
    qualifier => "stable",
  }

  hudson::hudson { "1.532.2":
    type      => "jenkins",
    qualifier => "stable",
  }

  hudson::hudson { "jenkins-latest":
    type      => "jenkins",
    qualifier => "latest",
  }

  /* Sites */

  hudson::site { "hudson-3.0.1":
    envtype => "hudson",
    version => "3.0.1",
    port    => 9031,
    require => Hudson["3.0.1"],
  }

  hudson::site { "hudson-3.1.2":
    envtype => "hudson",
    version => "3.1.2",
    port    => 9042,
    envdefault => true,
    require => Hudson["3.1.2"],
  }

  hudson::site { "jenkins-1.509.4":
    envtype => "jenkins",
    version => "1.509.4",
    port    => 9134,
    envdefault => true,
    require => Hudson["1.509.4"],
  }

  hudson::site { "jenkins-1.532.2":
    envtype => "jenkins",
    version => "1.532.2",
    port    => 9142,
    require => Hudson["1.532.2"],
  }

  hudson::site { "jenkins-latest":
    envtype => "jenkins",
    version => "jenkins-latest",
    port    => 9110,
    require => Hudson["jenkins-latest"],
  }

}