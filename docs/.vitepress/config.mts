import { defineConfig } from 'vitepress'

const repository = 'https://github.com/fyzure/lucky-skills'

function optimizeApiRouteSections(html: string) {
  if (!html.includes('<h2 id="_2fa" tabindex="-1">')) return html

  let sectionOpened = false
  const withSections = html.replace(/<h2 id="[^"]+" tabindex="-1">/g, (heading) => {
    const prefix = sectionOpened ? '</section>' : ''
    sectionOpened = true
    return `${prefix}<section class="route-module">${heading}`
  })

  return sectionOpened
    ? withSections.replace(
        '</div></div><div class="page-meta">',
        '</section></div></div><div class="page-meta">'
      )
    : withSections
}

function foldDenseApiRouteCells(html: string) {
  if (!html.includes('<h1 id="api-路由参考"')) return html

  const previewItems = 5

  return html.replace(/<td>([\s\S]*?)<\/td>/g, (cell, content: string) => {
    const codeCount = (content.match(/<code>/g) ?? []).length
    if (codeCount < 8) return cell

    let splitAt = -1
    let searchFrom = 0

    for (let index = 0; index < previewItems; index += 1) {
      const closingCode = content.indexOf('</code>', searchFrom)
      if (closingCode === -1) return cell
      splitAt = closingCode + '</code>'.length
      searchFrom = splitAt
    }

    const preview = content.slice(0, splitAt).replace(/\s*,\s*$/, '')
    const rest = content.slice(splitAt).replace(/^\s*,\s*/, '')
    const remainingItems = codeCount - previewItems

    return `<td><span class="cell-fold-preview">${preview}</span><details class="cell-fold"><summary><span class="cell-fold-more">+${remainingItems} 项</span><span class="cell-fold-less">收起</span></summary><span class="cell-fold-rest">${rest}</span></details></td>`
  })
}

export default defineConfig({
  lang: 'zh-CN',
  title: 'Lucky Skills',
  description: 'Lucky v3 OpenToken API、Agent Skill 与安全自动化文档',
  base: '/lucky-skills/',
  cleanUrls: true,
  mpa: true,
  lastUpdated: true,
  outDir: '../dist/lucky-skills',
  vite: {
    build: {
      emptyOutDir: true
    }
  },
  sitemap: {
    hostname: 'https://docs.fyzure.fyi/lucky-skills/'
  },
  transformHtml(html) {
    const withoutUnusedIcons = html.replace(
      /\s*<link rel="preload stylesheet" href="\/lucky-skills\/vp-icons\.css" as="style">/,
      ''
    )
    const withPublishedEvidenceLinks = withoutUnusedIcons.replace(
      /href="\.\.\/evidence\/(lucky-v3-(?:endpoints|runtime-verification)\.json)"/g,
      'href="/lucky-skills/evidence/$1"'
    )
    return optimizeApiRouteSections(foldDenseApiRouteCells(withPublishedEvidenceLinks))
  },
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/lucky-skills/favicon.svg' }],
    ['script', { type: 'module', src: '/lucky-skills/enhance.js' }],
    ['meta', { name: 'color-scheme', content: 'light dark' }],
    ['meta', { name: 'theme-color', content: '#ffffff', media: '(prefers-color-scheme: light)' }],
    ['meta', { name: 'theme-color', content: '#1b1b1f', media: '(prefers-color-scheme: dark)' }],
    ['meta', { name: 'robots', content: 'index,follow,max-image-preview:large' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Lucky Skills' }]
  ],
  themeConfig: {
    logo: {
      src: '/favicon.svg',
      alt: 'Lucky Skills'
    },
    nav: [
      { text: '指南', link: '/installation' },
      { text: 'API', link: '/generated/api-routes' },
      { text: 'OpenAPI', link: `${repository}/blob/main/openapi/lucky-v3.openapi.json` }
    ],
    sidebar: [
      {
        text: '开始使用',
        items: [
          { text: '项目概览', link: '/' },
          { text: '安装', link: '/installation' },
          { text: '快速开始', link: '/quickstart' },
          { text: '凭据管理', link: '/credentials' },
          { text: '鉴权与安全', link: '/authentication' }
        ]
      },
      {
        text: '使用指南',
        items: [
          { text: 'API 客户端与 CLI', link: '/api-client' },
          { text: '接口约定', link: '/conventions' },
          { text: 'WebService 反向代理语义', link: '/webservice-reverse-proxy' },
          { text: '模块指南', link: '/modules' }
        ]
      },
      {
        text: '参考',
        items: [
          { text: '完整 API 路由', link: '/generated/api-routes' },
          { text: '证据与覆盖范围', link: '/evidence-and-limitations' },
          { text: '资料来源', link: '/sources' }
        ]
      },
      {
        text: '项目',
        items: [
          { text: 'GitHub 仓库', link: repository },
          { text: '贡献指南', link: `${repository}/blob/main/CONTRIBUTING.md` },
          { text: '安全策略', link: `${repository}/blob/main/SECURITY.md` }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: repository }
    ],
    editLink: {
      pattern: `${repository}/edit/main/docs/:path`,
      text: '在 GitHub 上编辑此页'
    },
    search: {
      provider: 'local',
      options: {
        translations: {
          button: {
            buttonText: '搜索',
            buttonAriaLabel: '搜索'
          },
          modal: {
            displayDetails: '显示详细列表',
            resetButtonTitle: '重置搜索',
            backButtonTitle: '关闭搜索',
            noResultsText: '没有找到相关结果',
            footer: {
              selectText: '选择',
              selectKeyAriaLabel: '回车键',
              navigateText: '切换',
              navigateUpKeyAriaLabel: '向上箭头',
              navigateDownKeyAriaLabel: '向下箭头',
              closeText: '关闭',
              closeKeyAriaLabel: 'Esc 键'
            }
          }
        }
      }
    },
    outline: {
      level: [2, 3],
      label: '本页目录'
    },
    docFooter: {
      prev: '上一页',
      next: '下一页'
    },
    lastUpdated: {
      text: '最后更新'
    },
    footer: {
      message: '非 Lucky 官方项目。仅对你拥有或获授权管理的实例使用。',
      copyright: 'Lucky Skills'
    }
  }
})
