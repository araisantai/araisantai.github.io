---
---

(() => {
  const root = document.documentElement;
  const toggle = document.querySelector("[data-theme-toggle]");
  const searchInput = document.querySelector("[data-search-input]");
  const searchResults = document.querySelector("[data-search-results]");
  const searchUrl = "{{ '/search.json' | relative_url }}";
  let posts = [];

  const getPreferredTheme = () => {
    try {
      const saved = localStorage.getItem("theme");
      if (saved) return saved;
    } catch (error) {}

    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  };

  const setTheme = (theme) => {
    root.dataset.theme = theme;
    if (toggle) {
      toggle.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} mode`);
      toggle.innerHTML = `<span aria-hidden="true">${theme === "dark" ? "☀" : "☾"}</span>`;
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
      searchResults.innerHTML = `<p>No matching notes yet.</p>`;
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
      })
      .catch(() => {
        searchResults.innerHTML = `<p>Search index is unavailable while the site is building.</p>`;
      });

    searchInput.addEventListener("input", (event) => {
      const query = event.target.value;
      renderResults(searchPosts(query), query.trim());
    });
  }
})();
