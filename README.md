# Local Web Search for Claude Code

Gives Claude Code public repository, package, documentation, and paper search through a local SearXNG container. Search needs no paid search API. Claude still uses your own model account; public query text goes to the selected source.

The qualified workflows are finding the official link to a known GitHub repository or arXiv paper. Enter the repository owner and name or the exact paper title. This source tree also includes two reader improvements tested on recorded PostgreSQL and GitHub documentation. Broad search and other specialist routes are available for evaluation.

**Broad search and recent-news discovery are experimental.** For an important factual claim, start with a known publisher URL and check the original passage. The verified-evidence command below can return a checked quotation or report that it could not verify the claim.

## First run

Install **Python 3.10+**, **Node.js 24 with npm**, **Podman**, **Claude Code**, and the standard `patch` utility. On macOS, start your Podman VM with `podman machine start`. For a new Podman installation, run `podman machine init` once first.

From this folder, run setup once.

```sh
./web-search setup
```

Setup downloads the pinned image and packages if needed, builds the MCP server, and generates a local profile for this machine. To use a Claude account, sign in through Claude Code, then run `./web-search`.

Keep `web-search`, `local-search/` and `evaluation/mcp_selection/` together. The last directory contains the pinned npm dependency, MCP build patches and Claude launcher support used at runtime. Each installation generates its own profile, build and local state.

When updating an existing checkout, close its dedicated Claude session and run `./web-search setup --rebuild`. Setup reports the backup directory and keeps your pacing database. To roll back, close the dedicated session, move the current `local-search/build-budgeted` aside, then move the saved `build-budgeted` back into `local-search/`. If the backup includes `mcp.json` and `routing.json`, park the current copies and restore both saved files alongside the build. Run `./web-search status` to check the result.

### Using a model gateway

The launcher reads gateway settings from the terminal environment. If you keep those settings in `~/.claude/settings.json`, make them available in the terminal before launching. Run the following in Bash or Zsh with the URL and model ID supplied by your provider.

```sh
export ANTHROPIC_BASE_URL='YOUR_GATEWAY_URL'
export ANTHROPIC_MODEL='YOUR_PROVIDER_MODEL_ID'
printf 'API key: '
IFS= read -rs ANTHROPIC_API_KEY
export ANTHROPIC_API_KEY
printf '\n'
./web-search
```

The prompt reads your key without displaying it or saving it in shell history. If your provider supports reasoning effort, you can also set `CLAUDE_CODE_EFFORT_LEVEL` before launching. [Claude Code environment variables](https://code.claude.com/docs/en/env-vars)

## Using search

For one evidence-focused question, use `./web-search start --verified-evidence --prompt 'Your question'`. This mode checks selected quotations against the retrieved publisher text and reports what could not be verified. It uses Claude Code's structured output and the configured model connection. Normal interactive search remains available through `./web-search`.

Ask, for example, “Find the official serde crate and link to its package page,” or “Search the web for the official PostgreSQL write-ahead log documentation.” For a known public URL, paste it directly. The agent tries a relevant specialist first and uses general web search if needed.

- **Repositories and packages:** GitHub public repositories, npm’s official registry, crates.io, and Docker Hub. Ask for a package by its exact name. Claude can verify the current npm `latest` tag directly from the registry.
- **Models and datasets:** Hugging Face search and a direct public account catalogue. Ask for the newest models from a named public account. Verify release dates in the model card or publisher announcement.
- **Developer help:** MDN and Stack Overflow.
- **Internet standards:** Search for a named networking standard such as “HPACK HTTP header compression.” The evidence search can find an RFC through IETF metadata. Open the original RFC to verify the answer.
- **Research:** arXiv, Crossref by title or author, and PubMed. An exact DOI can be read directly from Crossref. Cite the original record and treat search snippets as leads.
- **General search:** The default tie-break is DuckDuckGo → Yahoo → FreeSerp. The adaptive router can adjust the order based on the query and observed usefulness. Each installation tracks its own 30-second intervals and saved provider pauses.

An installation behind a shared office or VPN address can still encounter upstream limits even when its own pacing permits a request. A configured engine can be paused or unavailable. See `./web-search status` for saved eligibility and verify important findings against the publisher.

For a single leading restriction such as `site:docs.python.org asyncio TaskGroup`, results must match that host or one of its subdomains. If the first source provides only outside results, the router can try the next eligible source within the same request limits.

FreeSerp's page index can be temporarily unavailable while its homepage index still responds. The local FreeSerp adapter reports that event as an upstream error and the router applies its existing backoff. A successful empty page-index response remains an ordinary search result. [FreeSerp API documentation](https://freeserp.ai/docs.php#limits)

Use `./web-search status` for local status and `./web-search stop` to stop the service. A single container listens only on `127.0.0.1:8894` and uses one CPU and up to 256 MiB. Search tries engines serially with a shared deadline and per-source pacing. Status reports saved limits and pauses. Keep the generated profile and SQLite state local.

If a prerequisite is missing, install it and rerun setup. If port 8894 is occupied, stop the unrelated service only if you own it, or edit the port in `local-search/service.json` before setup. If you move an installed folder, move its generated `local-search/mcp.json` aside and rerun setup to regenerate absolute paths.

## Third-party software

The build installs [mcp-searxng 2.11.0](https://www.npmjs.com/package/mcp-searxng/v/2.11.0) and applies the local patches included here. See [its MIT license](LICENSE-mcp-searxng). Setup pulls [SearXNG](https://github.com/searxng/searxng) under its [AGPL-3.0 license](https://github.com/searxng/searxng/blob/master/LICENSE). The included [FreeSerp adapter](local-search/freeserp.py) uses [AGPL-3.0-or-later](LICENSE-AGPL-3.0). The image and npm packages are fetched during setup.
