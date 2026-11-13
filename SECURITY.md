# Security policy

pymxc is a sandboxing tool, so a flaw in it can leave a program less contained
than its user believes. Reports are welcome.

## Reporting a vulnerability

Please report it privately, not in a public issue:

1. Open the repository on GitHub: <https://github.com/Jay-N-J/pyMXC>
2. Go to the **Security** tab and choose **Report a vulnerability**.

Include what you did, what you expected the sandbox to block, and what
happened instead. The output of `python pymxc.py --probe` (the Windows build
and the policy version) helps a lot.

You should get a first answer within a week. This is a spare-time project
maintained by one person, so fixes take as long as they take; you will be
told what is planned.

## What counts

- A sandboxed program reaching files, network addresses or other resources
  that the settings in use say it cannot reach.
- A sandboxed program causing code to run outside the sandbox.
- Settings that are silently weaker than the documentation says.
- A crash or hang in the part of pymxc that runs outside the sandbox, caused
  by the sandboxed program.

Not a pymxc vulnerability, though still worth knowing about:

- Limits listed under "Limits you should know" in the README.
- Flaws in the Windows feature itself (process security environments). Those
  belong with Microsoft; pymxc is an independent project and is not made,
  endorsed or supported by Microsoft.

## Supported versions

Only the latest release gets fixes. pymxc is at version 0.x: settings and
behaviour may change between releases.
