---
---

// Site language: hand-written interface strings + Google Translate for post content.
// English is the source language; choosing another one is remembered in localStorage.
(() => {
  const root = document.documentElement;
  const LANGS = ["zh-CN", "en", "fr", "ru", "es", "ja", "id"];

  const STRINGS = {
    en: {
      "skip": "Skip to content",
      "nav.categories": "Categories",
      "nav.about": "About Me",
      "lang.label": "Language",
      "theme.toDark": "Switch to dark mode",
      "theme.toLight": "Switch to light mode",
      "topic.cybersecurity": "Cyber Security",
      "topic.finance": "Finance",
      "topic.books": "Books",
      "cat.latest": "Latest {topic} notes",
      "cat.find": "Find a note",
      "cat.searchHint": "Search this {topic} notebook.",
      "cat.searchPlaceholder": "Search {topic}...",
      "cat.empty": "No posts in this category yet.",
      "search.none": "No matching notes yet.",
      "search.unavailable": "Search index is unavailable while the site is building.",
      "post.back": "← {topic}",
      "post.minRead": "{n} min read",
      "post.moreFrom": "More from {topic}",
      "post.seeAll": "See all {topic} notes →",
      "footer.journal": "A personal journal by {author}",
      "code.copy": "Copy",
      "code.copied": "Copied",
      "code.pressCtrlC": "Press Ctrl+C",
      "code.aria": "Copy code to clipboard",
      "code.label": "code"
    },
    "zh-CN": {
      "skip": "跳到内容",
      "nav.categories": "分类",
      "nav.about": "关于我",
      "lang.label": "语言",
      "theme.toDark": "切换到深色模式",
      "theme.toLight": "切换到浅色模式",
      "topic.cybersecurity": "网络安全",
      "topic.finance": "财务",
      "topic.books": "书籍",
      "cat.latest": "最新{topic}笔记",
      "cat.find": "查找笔记",
      "cat.searchHint": "搜索{topic}笔记本。",
      "cat.searchPlaceholder": "搜索{topic}…",
      "cat.empty": "此分类暂无文章。",
      "search.none": "暂无匹配的笔记。",
      "search.unavailable": "网站构建期间搜索索引不可用。",
      "post.back": "← {topic}",
      "post.minRead": "阅读约 {n} 分钟",
      "post.moreFrom": "更多{topic}内容",
      "post.seeAll": "查看全部{topic}笔记 →",
      "footer.journal": "{author} 的个人日志",
      "code.copy": "复制",
      "code.copied": "已复制",
      "code.pressCtrlC": "请按 Ctrl+C",
      "code.aria": "将代码复制到剪贴板",
      "code.label": "代码"
    },
    fr: {
      "skip": "Aller au contenu",
      "nav.categories": "Catégories",
      "nav.about": "À propos de moi",
      "lang.label": "Langue",
      "theme.toDark": "Passer au mode sombre",
      "theme.toLight": "Passer au mode clair",
      "topic.cybersecurity": "Cybersécurité",
      "topic.finance": "Finance",
      "topic.books": "Livres",
      "cat.latest": "Dernières notes : {topic}",
      "cat.find": "Trouver une note",
      "cat.searchHint": "Rechercher dans le carnet {topic}.",
      "cat.searchPlaceholder": "Rechercher dans {topic}...",
      "cat.empty": "Aucun article dans cette catégorie pour le moment.",
      "search.none": "Aucune note correspondante pour le moment.",
      "search.unavailable": "L’index de recherche est indisponible pendant la génération du site.",
      "post.back": "← {topic}",
      "post.minRead": "{n} min de lecture",
      "post.moreFrom": "Plus de notes : {topic}",
      "post.seeAll": "Voir toutes les notes : {topic} →",
      "footer.journal": "Un journal personnel de {author}",
      "code.copy": "Copier",
      "code.copied": "Copié",
      "code.pressCtrlC": "Appuyez sur Ctrl+C",
      "code.aria": "Copier le code dans le presse-papiers",
      "code.label": "code"
    },
    ru: {
      "skip": "Перейти к содержимому",
      "nav.categories": "Категории",
      "nav.about": "Обо мне",
      "lang.label": "Язык",
      "theme.toDark": "Включить тёмную тему",
      "theme.toLight": "Включить светлую тему",
      "topic.cybersecurity": "Кибербезопасность",
      "topic.finance": "Финансы",
      "topic.books": "Книги",
      "cat.latest": "Последние заметки: {topic}",
      "cat.find": "Найти заметку",
      "cat.searchHint": "Поиск по разделу «{topic}».",
      "cat.searchPlaceholder": "Поиск: {topic}...",
      "cat.empty": "В этой категории пока нет записей.",
      "search.none": "Подходящих заметок пока нет.",
      "search.unavailable": "Поисковый индекс недоступен во время сборки сайта.",
      "post.back": "← {topic}",
      "post.minRead": "{n} мин чтения",
      "post.moreFrom": "Ещё из раздела «{topic}»",
      "post.seeAll": "Все заметки: {topic} →",
      "footer.journal": "Личный дневник: {author}",
      "code.copy": "Копировать",
      "code.copied": "Скопировано",
      "code.pressCtrlC": "Нажмите Ctrl+C",
      "code.aria": "Скопировать код в буфер обмена",
      "code.label": "код"
    },
    es: {
      "skip": "Ir al contenido",
      "nav.categories": "Categorías",
      "nav.about": "Sobre mí",
      "lang.label": "Idioma",
      "theme.toDark": "Cambiar al modo oscuro",
      "theme.toLight": "Cambiar al modo claro",
      "topic.cybersecurity": "Ciberseguridad",
      "topic.finance": "Finanzas",
      "topic.books": "Libros",
      "cat.latest": "Últimas notas de {topic}",
      "cat.find": "Buscar una nota",
      "cat.searchHint": "Busca en el cuaderno de {topic}.",
      "cat.searchPlaceholder": "Buscar en {topic}...",
      "cat.empty": "Todavía no hay publicaciones en esta categoría.",
      "search.none": "Aún no hay notas que coincidan.",
      "search.unavailable": "El índice de búsqueda no está disponible mientras se compila el sitio.",
      "post.back": "← {topic}",
      "post.minRead": "{n} min de lectura",
      "post.moreFrom": "Más de {topic}",
      "post.seeAll": "Ver todas las notas de {topic} →",
      "footer.journal": "Un diario personal de {author}",
      "code.copy": "Copiar",
      "code.copied": "Copiado",
      "code.pressCtrlC": "Pulsa Ctrl+C",
      "code.aria": "Copiar el código al portapapeles",
      "code.label": "código"
    },
    ja: {
      "skip": "コンテンツへ移動",
      "nav.categories": "カテゴリー",
      "nav.about": "自己紹介",
      "lang.label": "言語",
      "theme.toDark": "ダークモードに切り替え",
      "theme.toLight": "ライトモードに切り替え",
      "topic.cybersecurity": "サイバーセキュリティ",
      "topic.finance": "ファイナンス",
      "topic.books": "本",
      "cat.latest": "{topic}の最新ノート",
      "cat.find": "ノートを探す",
      "cat.searchHint": "{topic}のノートを検索します。",
      "cat.searchPlaceholder": "{topic}を検索…",
      "cat.empty": "このカテゴリーにはまだ投稿がありません。",
      "search.none": "一致するノートはまだありません。",
      "search.unavailable": "サイトのビルド中は検索インデックスを利用できません。",
      "post.back": "← {topic}",
      "post.minRead": "{n}分で読めます",
      "post.moreFrom": "{topic}の他の記事",
      "post.seeAll": "{topic}のノートをすべて見る →",
      "footer.journal": "{author}の個人的な記録",
      "code.copy": "コピー",
      "code.copied": "コピーしました",
      "code.pressCtrlC": "Ctrl+C を押してください",
      "code.aria": "コードをクリップボードにコピー",
      "code.label": "コード"
    },
    id: {
      "skip": "Langsung ke konten",
      "nav.categories": "Kategori",
      "nav.about": "Tentang Saya",
      "lang.label": "Bahasa",
      "theme.toDark": "Beralih ke mode gelap",
      "theme.toLight": "Beralih ke mode terang",
      "topic.cybersecurity": "Keamanan Siber",
      "topic.finance": "Keuangan",
      "topic.books": "Buku",
      "cat.latest": "Catatan {topic} terbaru",
      "cat.find": "Cari catatan",
      "cat.searchHint": "Cari di buku catatan {topic}.",
      "cat.searchPlaceholder": "Cari {topic}...",
      "cat.empty": "Belum ada tulisan di kategori ini.",
      "search.none": "Belum ada catatan yang cocok.",
      "search.unavailable": "Indeks pencarian tidak tersedia saat situs sedang dibangun.",
      "post.back": "← {topic}",
      "post.minRead": "{n} menit baca",
      "post.moreFrom": "Lainnya dari {topic}",
      "post.seeAll": "Lihat semua catatan {topic} →",
      "footer.journal": "Jurnal pribadi oleh {author}",
      "code.copy": "Salin",
      "code.copied": "Disalin",
      "code.pressCtrlC": "Tekan Ctrl+C",
      "code.aria": "Salin kode ke papan klip",
      "code.label": "kode"
    }
  };

  const readLang = () => {
    try {
      const saved = localStorage.getItem("lang");
      if (LANGS.includes(saved)) return saved;
    } catch (error) {}
    return "en";
  };

  const lang = readLang();

  const t = (key, params = {}) => {
    const text = (STRINGS[lang] && STRINGS[lang][key]) || STRINGS.en[key] || key;
    return text.replace(/\{(\w+)\}/g, (match, name) => {
      if (name === "topic" && params.topic) return t(`topic.${params.topic}`);
      return params[name] ?? match;
    });
  };

  const paramsFor = (el) => ({
    topic: el.dataset.i18nTopic,
    n: el.dataset.i18nN,
    author: el.dataset.i18nAuthor
  });

  const applyStrings = () => {
    root.lang = lang === "zh-CN" ? "zh-CN" : lang;
    root.dir = "ltr";

    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.classList.add("notranslate");
      el.setAttribute("translate", "no");
      if (lang !== "en") el.textContent = t(el.dataset.i18n, paramsFor(el));
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      if (lang !== "en") el.placeholder = t(el.dataset.i18nPlaceholder, paramsFor(el));
    });

    const dateFormat = new Intl.DateTimeFormat(lang, { year: "numeric", month: "short", day: "numeric" });
    document.querySelectorAll("time[data-i18n-date]").forEach((el) => {
      el.classList.add("notranslate");
      el.setAttribute("translate", "no");
      const value = new Date(el.getAttribute("datetime"));
      if (lang !== "en" && !Number.isNaN(value.getTime())) el.textContent = dateFormat.format(value);
    });

    // Never machine-translate code.
    document.querySelectorAll("pre, code, .highlighter-rouge").forEach((el) => {
      el.classList.add("notranslate");
      el.setAttribute("translate", "no");
    });
  };

  // ---- Google Translate (post and page content) ---------------------------
  const COOKIE = "googtrans";
  const cookieDomains = () => {
    const host = location.hostname;
    const parts = host.split(".");
    const domains = ["", host];
    if (parts.length > 1) domains.push("." + parts.slice(-2).join("."));
    return domains;
  };

  const setGoogleCookie = (target) => {
    cookieDomains().forEach((domain) => {
      const scope = domain ? `; domain=${domain}` : "";
      if (target === "en") {
        document.cookie = `${COOKIE}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/${scope}`;
      } else {
        document.cookie = `${COOKIE}=/en/${target}; path=/${scope}`;
      }
    });
  };

  const loadGoogleTranslate = () => {
    if (window.google?.translate || document.querySelector("script[data-google-translate]")) return;
    window.arainotesTranslateInit = () => {
      new window.google.translate.TranslateElement({
        pageLanguage: "en",
        includedLanguages: LANGS.filter((code) => code !== "en").join(","),
        autoDisplay: false
      }, "google_translate_element");
    };
    const script = document.createElement("script");
    script.src = "https://translate.google.com/translate_a/element.js?cb=arainotesTranslateInit";
    script.async = true;
    script.dataset.googleTranslate = "";
    document.head.appendChild(script);
  };

  const setLanguage = (next) => {
    if (!LANGS.includes(next) || next === lang) return;
    try {
      localStorage.setItem("lang", next);
    } catch (error) {}
    setGoogleCookie(next);
    // Reload so every string, date and Google's translation start from the original English page.
    location.reload();
  };

  const init = () => {
    applyStrings();

    const select = document.querySelector("[data-lang-select]");
    if (select) {
      select.value = lang;
      select.addEventListener("change", () => setLanguage(select.value));
    }

    if (lang === "en") {
      setGoogleCookie("en");
    } else {
      setGoogleCookie(lang);
      loadGoogleTranslate();
    }
  };

  window.arainotesI18n = { lang, t };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
