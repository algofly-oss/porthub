import Guide from "@/components/Guide";
import { guideArticles } from "@/content/guide";
export default function GuideArticle({ slug }: { slug: string }) { return <Guide slug={slug} />; }
export function getStaticPaths() { return { paths: guideArticles.filter(article=>article.slug!=="overview").map(article=>({params:{slug:article.slug}})), fallback: false }; }
export function getStaticProps({ params }: { params: { slug: string } }) { return { props: { slug: params.slug } }; }
