/* eslint-disable */
/* eslint-enable indent, comma-dangle, semi, eol-last, quotes, switch-colon-spacing, space-before-blocks, no-dupe-keys, ident, linebreak-style */

const path = require("node:path");
const { runloop } = require("node-runloop");
const { existsSync, promises, readFileSync, readdirSync } = require("node:fs");


async function main() {
  const BUILD_DIR = path.join(process.cwd(), process.env.BUILD_DIR || "dist");

  if(!existsSync(BUILD_DIR)) {
    throw new Error("No build directory found");
  }

  await runloop.createTask(() => rimraf(BUILD_DIR, [
    {
      rule: "endsWith",
      value: [".spec.js", ".spec.d.ts"],
    },
  ])).wait();

  const json = JSON.parse(readFileSync(path.join(process.cwd(), "package.json")));
  const buildJson = JSON.parse(readFileSync(path.join(process.cwd(), "package.build.json")));

  if("dependencies" in json) {
    buildJson.dependencies = json.dependencies;
  } else {
    delete buildJson.dependencies;
  }

  buildJson.version = json.version;

  await runloop.createTask(() => promises.writeFile(
    path.join(process.cwd(), "package.build.json"),
    JSON.stringify(buildJson, null, 2) // eslint-disable-line comma-dangle
  )).wait();

  await runloop.createTask(() => promises.copyFile(
    path.join(process.cwd(), "package.build.json"),
    path.join(BUILD_DIR, "package.json") // eslint-disable-line comma-dangle
  )).wait();


  if(process.env.NODE_ENV === "production") {
    await rimraf(BUILD_DIR, [
      {
        rule: "exact",
        value: ["test.js", "test.d.ts"],
      },
    ]);
  }
}


/**
 * 
 * @param {string} path 
 * @param {{ rule: 'endsWith' | 'startsWith' | 'exact'; value: string[] }[]} condition 
 */
async function rimraf(pathname, condition) {
  const stat = await promises.stat(pathname);

  if(stat.isDirectory()) {
    for(const subpath of readdirSync(pathname)) {
      const current = path.join(pathname, subpath);
      const substat = await promises.stat(current);
      
      if(substat.isDirectory()) {
        await rimraf(current, condition);
        continue;
      }
      
      for(let i = 0; i < condition.length; i++) {
        switch(condition[i].rule) {
          case "endsWith": {
            if(condition[i].value.some(x => current.endsWith(x))) {
              await promises.unlink(current);
            }
          } break;
          case "exact": {
            if(condition[i].value.some(x => x === path.basename(current))) {
              await promises.unlink(current);
            }
          } break;
        }
      }
    }
  } else {
    for(let i = 0; i < condition.length; i++) {
      switch(condition[i].rule) {
        case "endsWith": {
          if(condition[i].value.some(x => pathname.endsWith(x))) {
            await promises.unlink(pathname);
          }
        } break;
        case "exact": {
          if(condition[i].value.some(x => x === path.basename(pathname))) {
            await promises.unlink(pathname);
          }
        } break;
      }
    }
  }
}


runloop.run(main);
