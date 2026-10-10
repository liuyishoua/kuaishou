# coding=utf-8
import os

from loguru import logger

from ks_apis.kuaishou_api import KuaishouAPI
from utils.common_util import init
from utils.data_util import handle_work_info, download_work, save_to_xlsx


class Data_Spider():
    """快手数据爬虫入口（对齐 DouYin_Spider/main.py 的 Data_Spider 结构）。"""

    def __init__(self):
        self.kuaishou_apis = KuaishouAPI()

    def spider_work(self, auth, photo_id_or_url: str, proxies=None):
        """
        爬取一个作品的信息（从推荐流/评论确认，归一化输出）。
        :param auth: 用户认证信息（KuaishouAuth）。
        :param photo_id_or_url: 作品链接或 photoId。
        :return: 归一化 work_info。
        """
        res_json = self.kuaishou_apis.get_work_info(auth, photo_id_or_url)
        # 作品详情随推荐流下发，这里以评论响应校验存在性；photo 结构从 feed 内取更完整
        work_info = handle_work_info(res_json if 'photo' in res_json else {'photo': {'id': _pid(photo_id_or_url)}})
        logger.info(f'爬取作品信息 {photo_id_or_url}')
        return work_info

    def spider_some_work(self, auth, works: list, base_path: dict, save_choice: str, excel_name: str = '', proxies=None):
        """
        爬取一些作品的信息。
        :param auth: 用户认证信息。
        :param works: 作品链接/ID 列表。
        :param base_path: 保存路径。
        :param save_choice: 保存方式 all/media/media-video/media-image/excel。
        :param excel_name: excel 文件名。
        """
        if (save_choice == 'all' or save_choice == 'excel') and excel_name == '':
            raise ValueError('excel_name 不能为空')
        work_list = []
        for work_url in works:
            work_info = self.spider_work(auth, work_url)
            work_list.append(work_info)
        for work_info in work_list:
            if save_choice == 'all' or 'media' in save_choice:
                download_work(work_info, base_path['media'], save_choice)
        if save_choice == 'all' or save_choice == 'excel':
            file_path = os.path.abspath(os.path.join(base_path['excel'], f'{excel_name}.xlsx'))
            save_to_xlsx(work_list, file_path)

    def spider_user_all_work(self, auth, user_id: str, base_path: dict, save_choice: str, excel_name: str = '', proxies=None):
        """
        爬取一个用户的所有作品（🔒 需签名器就绪）。
        :param auth: 用户认证信息。
        :param user_id: 用户 ID（eid/userId）。
        :param base_path: 保存路径。
        :param save_choice: 保存方式。
        :param excel_name: excel 文件名。
        """
        feed_list = self.kuaishou_apis.get_user_all_work(auth, user_id)
        logger.info(f'用户 {user_id} 作品数量: {len(feed_list)}')
        if save_choice == 'all' or save_choice == 'excel':
            excel_name = str(user_id)
        work_info_list = []
        for feed in feed_list:
            work_info = handle_work_info(feed)
            work_info_list.append(work_info)
            logger.info(f'爬取作品信息 {work_info["work_url"]}')
            if save_choice == 'all' or 'media' in save_choice:
                download_work(work_info, base_path['media'], save_choice)
        if save_choice == 'all' or save_choice == 'excel':
            file_path = os.path.abspath(os.path.join(base_path['excel'], f'{excel_name}.xlsx'))
            save_to_xlsx(work_info_list, file_path)

    def spider_some_search_work(self, auth, query: str, require_num: int, base_path: dict, save_choice: str,
                                excel_name: str = '', proxies=None):
        """
        搜索指定关键词的作品（🔒 需签名器就绪）。
        :param auth: 用户认证信息。
        :param query: 搜索关键字。
        :param require_num: 期望数量。
        :param base_path: 保存路径。
        :param save_choice: 保存方式。
        :param excel_name: excel 文件名。
        """
        feed_list = self.kuaishou_apis.search_some_feed(auth, query, require_num)
        logger.info(f'搜索关键词 {query} 作品数量: {len(feed_list)}')
        if save_choice == 'all' or save_choice == 'excel':
            excel_name = query
        work_info_list = []
        for feed in feed_list:
            work_info = handle_work_info(feed)
            work_info_list.append(work_info)
            logger.info(f'爬取作品信息 {work_info["work_url"]}')
            if save_choice == 'all' or 'media' in save_choice:
                download_work(work_info, base_path['media'], save_choice)
        if save_choice == 'all' or save_choice == 'excel':
            file_path = os.path.abspath(os.path.join(base_path['excel'], f'{excel_name}.xlsx'))
            save_to_xlsx(work_info_list, file_path)

    def spider_feed_hot(self, auth, require_num: int, base_path: dict, save_choice: str, excel_name: str = '', proxies=None):
        """
        爬取推荐流（精彩推荐）作品。
        :param auth: 用户认证信息。
        :param require_num: 期望数量。
        :param base_path: 保存路径。
        :param save_choice: 保存方式。
        :param excel_name: excel 文件名。
        """
        if (save_choice == 'all' or save_choice == 'excel') and excel_name == '':
            raise ValueError('excel_name 不能为空')
        feed_list = self.kuaishou_apis.get_some_feed_hot(auth, require_num)
        logger.info(f'推荐流作品数量: {len(feed_list)}')
        work_info_list = []
        for feed in feed_list:
            work_info = handle_work_info(feed)
            work_info_list.append(work_info)
            logger.info(f'爬取作品信息 {work_info["work_url"]}')
            if save_choice == 'all' or 'media' in save_choice:
                download_work(work_info, base_path['media'], save_choice)
        if save_choice == 'all' or save_choice == 'excel':
            file_path = os.path.abspath(os.path.join(base_path['excel'], f'{excel_name}.xlsx'))
            save_to_xlsx(work_info_list, file_path)


def _pid(s: str) -> str:
    s = str(s)
    if '/' in s:
        return s.rstrip('/').split('/')[-1].split('?')[0]
    return s


if __name__ == '__main__':
    """
        此文件为爬虫的入口文件，可以直接运行。
        ks_apis/kuaishou_api.py 为数据接口文件，包含快手 www 全部数据接口。
        ks_apis/publish_api.py 为发布接口文件，包含 cp 图文/视频发布接口。
        签名见 utils/sign/：__NS_hxfalcon 与 __NS_sig3 已纯算实现，kww 透传 cookie kwfv1。
    """
    auth, base_path = init()

    data_spider = Data_Spider()
    # save_choice: all / media / media-video / media-image / excel
    # save_choice 为 excel 或 all 时，excel_name 不能为空

    # 1 推荐流（当前线上 feed/hot 可能因版本合同漂移返回 400）
    data_spider.spider_feed_hot(auth, 20, base_path, 'excel', 'feed_hot')

    # 2 爬取一些作品（评论/校验，直连）
    # works = ['https://www.kuaishou.com/short-video/<photo_id>']
    # data_spider.spider_some_work(auth, works, base_path, 'all', 'test')

    # 3 搜索作品（🔒 需签名器就绪）
    # data_spider.spider_some_search_work(auth, '美食', 20, base_path, 'all')

    # 4 用户全部作品（🔒 需签名器就绪）
    # data_spider.spider_user_all_work(auth, '<eid>', base_path, 'all')
