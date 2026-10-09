// Test child: prints the names of its environment variables, the values of
// only the variables named on the command line, and its own arguments.
const [, , ...args] = process.argv;
const separator = args.indexOf("--");
const requested = separator === -1 ? args : args.slice(0, separator);
const echoed = separator === -1 ? [] : args.slice(separator + 1);
process.stdout.write(
  JSON.stringify({
    names: Object.keys(process.env).toSorted(),
    values: Object.fromEntries(requested.map((name) => [name, process.env[name] ?? null])),
    echoed,
  }),
);
