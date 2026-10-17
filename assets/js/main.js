---
---

(() => {
  const root = document.documentElement;
  const toggle = document.querySelector("[data-theme-toggle]");
  const searchInput = document.querySelector("[data-search-input]");
  const searchResults = document.querySelector("[data-search-results]");
  const searchUrl = searchInput?.dataset.searchUrl;
  let posts = [];

  const getPreferredTheme = () => {
    try {
      const saved = localStorage.getItem("theme");
      if (saved) return saved;
    } catch (error) {}

    return "light";
  };

  const setTheme = (theme) => {
    root.dataset.theme = theme;
    if (toggle) {
      toggle.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} mode`);
      toggle.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    }
    try {
      localStorage.setItem("theme", theme);
    } catch (error) {}
  };

  setTheme(getPreferredTheme());

  if (toggle) {
    toggle.addEventListener("click", () => {
      setTheme(root.dataset.theme === "dark" ? "light" : "dark");
    });
  }

  const renderResults = (items, query) => {
    if (!searchResults) return;

    if (!query) {
      searchResults.innerHTML = "";
      return;
    }

    if (!items.length) {
      searchResults.innerHTML = "<p>No matching notes yet.</p>";
      return;
    }

    searchResults.innerHTML = items
      .slice(0, 6)
      .map((post) => {
        const categories = post.categories.join(", ").replaceAll("-", " ");
        return `
          <a class="search-result" href="${post.url}">
            <strong>${post.title}</strong>
            <span>${categories}</span>
          </a>
        `;
      })
      .join("");
  };

  const searchPosts = (query) => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return [];

    return posts.filter((post) => {
      const haystack = [
        post.title,
        post.description,
        ...(post.categories || []),
        ...(post.tags || [])
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(normalized);
    });
  };

  if (searchInput && searchResults) {
    fetch(searchUrl)
      .then((response) => response.json())
      .then((data) => {
        posts = data;
        renderResults(searchPosts(searchInput.value), searchInput.value.trim());
      })
      .catch(() => {
        searchResults.innerHTML = "<p>Search index is unavailable while the site is building.</p>";
      });

    searchInput.addEventListener("input", (event) => {
      const query = event.target.value;
      renderResults(searchPosts(query), query.trim());
    });
  }

  // Code blocks: language label + copy button.
  const copyIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
  const checkIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 5 5 9-10"/></svg>';

  const copyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      let ok = false;
      try {
        ok = document.execCommand("copy");
      } catch (fallbackError) {}
      area.remove();
      return ok;
    }
  };

  document.querySelectorAll(".post-content pre").forEach((pre) => {
    const block = pre.closest(".highlighter-rouge") || pre;
    if (block.parentElement?.classList.contains("code-block")) return;

    const languageClass = [...block.classList].find((name) => name.startsWith("language-"));
    const language = languageClass ? languageClass.replace("language-", "") : "";

    const wrapper = document.createElement("div");
    wrapper.className = "code-block";
    const bar = document.createElement("div");
    bar.className = "code-block__bar";
    const label = document.createElement("span");
    label.textContent = language && language !== "plaintext" && language !== "text" ? language : "code";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "code-block__copy";
    button.setAttribute("aria-label", "Copy code to clipboard");
    button.innerHTML = `${copyIcon}<span>Copy</span>`;

    button.addEventListener("click", async () => {
      const code = pre.querySelector("code") || pre;
      const ok = await copyText(code.innerText.replace(/\n$/, ""));
      button.toggleAttribute("data-copied", ok);
      button.innerHTML = ok ? `${checkIcon}<span>Copied</span>` : `${copyIcon}<span>Press Ctrl+C</span>`;
      clearTimeout(button.resetTimer);
      button.resetTimer = setTimeout(() => {
        button.removeAttribute("data-copied");
        button.innerHTML = `${copyIcon}<span>Copy</span>`;
      }, 1800);
    });

    bar.append(label, button);
    block.parentNode.insertBefore(wrapper, block);
    wrapper.append(bar, block);
  });
})();
